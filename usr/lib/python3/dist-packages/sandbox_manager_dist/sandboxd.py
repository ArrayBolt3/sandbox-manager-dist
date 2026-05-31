#!/usr/bin/python3 -su

# Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
# See the file COPYING for copying conditions.

# pylint: disable=broad-exception-caught, too-many-lines

"""
sandboxd.py - The server component of sandbox-manager-dist. Handles sandbox
creation, deletion, management, and some forms of IPC.
"""

## TODO: Remove this in Debian Forky, Python 3.14+ will no longer require it
from __future__ import annotations

import logging
import multiprocessing as mp
import os
import queue
import select
import shutil
import sys
from dataclasses import dataclass
from multiprocessing.connection import Connection
from pathlib import Path
from queue import SimpleQueue
from threading import Thread, Lock
from typing import IO, NoReturn, Callable, Any

import sdnotify  # type: ignore
import schema  # type: ignore

from strict_config_parser import strict_config_parser

## Wildcard imports are safe here, every object in these modules will actually
## be used (eventually) by sandboxd and is named in a safe fashion.
# pylint: disable=wildcard-import
# pylint: disable=unused-wildcard-import
from .common import *
from .protocol import *

from .nspawn_manager import nspawn_manager_main


# pylint: disable=too-few-public-methods
class SandboxdGlobal:
    """
    Global variables for sandboxd.
    """

    pid_file_path: Path = Path(SmdCommon.state_dir, "pid")
    old_umask: int = 0

    sandbox_config_list: list[SandboxConfig] = []
    socket_list: list[SmdServerSocket] = []
    comm_thread_list: list[SandboxdCommThread] = []
    session_list_lock: Lock = Lock()
    nspawn_manager_list: list[NspawnManager] = []

    sdnotify_object: sdnotify.SystemdNotifier = sdnotify.SystemdNotifier()

    ## ctm = control to main
    ctm_read_fd: int = 0
    ctm_write_fd: int = 0
    ctm_read_pipe: IO[bytes] | None = None
    ctm_write_pipe: IO[bytes] | None = None
    control_session_queue: SimpleQueue[SmdSession] = SimpleQueue()
    add_control_socket_queue: SimpleQueue[SmdServerSocket] = SimpleQueue()
    remove_control_socket_queue: SimpleQueue[SmdServerSocket] = SimpleQueue()

    conf_schema: schema.Schema = schema.Schema(
        {
            "name": schema.And(
                str,
                schema.Regex(SmdCommon.sandbox_name_regex),
            ),
            "description": str,
            "root_vol_size": schema.And(
                int,
                lambda vol_size: 1 <= vol_size <= SmdCommon.max_vol_size,
            ),
            "data_vol_size": schema.And(
                int,
                lambda vol_size: 1 <= vol_size <= SmdCommon.max_vol_size,
            ),
            "memory": schema.And(
                int,
                lambda mem_size: 1 <= mem_size <= SmdCommon.max_mem_size,
            ),
            "cpu_weight": schema.And(
                int,
                lambda cpu_weight: 1 <= cpu_weight <= SmdCommon.max_cpu_weight,
            ),
            #"cpu_cores": int,
            "io_weight": schema.And(
                int,
                lambda io_weight: 1 <= io_weight <= SmdCommon.max_io_weight,
            ),
            "audio_enabled": bool,
            "wayland_enabled": bool,
            "x11_enabled": bool,
            "three_d_enabled": bool,
            "network_enabled": bool,
            "nested_sandboxing_enabled": bool,
            "shared_fso_list": [
                {
                    "read_write": bool,
                    "host_path": schema.And(
                        str,
                        schema.Regex(SmdCommon.absolute_path_regex),
                    ),
                    "sandbox_path": schema.And(
                        str,
                        schema.Regex(SmdCommon.absolute_path_regex),
                    ),
                },
            ],
            "shared_device_list": [
                schema.And(
                    str,
                    schema.Regex(SmdCommon.device_path_regex),
                ),
            ],
        }
    )


@dataclass
class SharedFsoConfig:
    """
    Configuration info for a shared folder or file.
    """

    read_write: bool
    host_path: str
    sandbox_path: str


# pylint: disable=too-many-instance-attributes
@dataclass
class SandboxConfig:
    """
    Configuration info for a sandbox.
    """

    uuid: str
    user_uid: int
    name: str
    description: str
    root_vol_size: int
    data_vol_size: int
    memory: int
    cpu_weight: int
    #cpu_cores: int
    io_weight: int
    audio_enabled: bool
    wayland_enabled: bool
    x11_enabled: bool
    three_d_enabled: bool  ## can't have number at start of var name
    network_enabled: bool
    nested_sandboxing_enabled: bool
    shared_fso_list: list[SharedFsoConfig]
    shared_device_list: list[str]


class HandlerProc:
    """
    A child process used to offload some of sandboxd's tasks.
    """

    def __init__(
        self, correlation_id: int, target_func: Callable[[Connection], None]
    ) -> None:
        self.correlation_id = correlation_id
        ## ptc = parent to child
        self.ptc_pipe: Connection
        ## ctp = child to parent
        self.ctp_pipe: Connection
        self.ptc_pipe, self.ctp_pipe = mp.Pipe(duplex=True)
        self.child_proc: mp.Process = mp.Process(
            target=target_func, args=(self.ctp_pipe,)
        )
        self.child_proc.start()


class NspawnManager:
    """
    A child process used to boot sandboxes and interface with them after
    bootup.
    """

    def __init__(self, sandbox_uuid: str, boot_mode: str) -> None:
        SmdCommon.validate_id(
            sandbox_uuid, [SmdValidateType.UUID], "UUID failed validation"
        )
        SmdCommon.validate_id(
            boot_mode,
            [SmdValidateType.BOOT_MODE],
            "Boot mode failed validation",
        )
        self.sandbox_uuid: str = sandbox_uuid
        self.boot_mode = boot_mode
        ## ptc = parent to child
        self.ptc_pipe: Connection
        ## ctp = child to parent
        self.ctp_pipe: Connection
        self.ptc_pipe, self.ctp_pipe = mp.Pipe(duplex=True)
        self.child_proc: mp.Process = mp.Process(
            target=nspawn_manager_main,
            args=(self.ctp_pipe, sandbox_uuid, boot_mode),
        )
        self.child_proc.start()


@dataclass
class SandboxdCommThreadShutdown:
    """
    Simple wrapper class used by comm threads to tell other comm threads that
    one is shutting down.
    """

    shutdown_thread: SandboxdCommThread


# pylint: disable=too-many-instance-attributes
class SandboxdCommThread:
    """
    All logic used for the server to communicate with a single comm client.
    Control clients are handled by a dedicated function that works with only
    one session at a time.
    """

    ## Notes on architecture concerns here:
    ##
    ## * There may have to be multiple "units of compute" (threads or separate
    ##   processes) for working with a single client. For instance, a client
    ##   can be simultaneously copying a file into a sandbox, creating a new
    ##   sandbox, and streaming the console from a third sandbox.
    ## * An action taken by one thread may result in notifications being sent
    ##   to clients that belong to other threads. For instance, when a new
    ##   sandbox is created, all relevant connected clients get notified.
    ## * Python's GIL means that only one thread can be executing Python code
    ##   at once, so if we have too many threads under load at once, the server
    ##   may bog down. Debian Trixie's build of Python is not free-threaded.
    ##
    ## Using Python multiprocessing may not be a good idea, because it could
    ## result in a lot of baggage from the core server carrying into child
    ## processes, much of which won't even be usable because we can't use the
    ## "fork" multiprocessing method thanks to the fact that we're already
    ## using multithreading. However, not using Python multiprocessing means
    ## that we would have to create separate communications protocols to allow
    ## the parent process to communicate with every possible child process.
    ## That sounds like a nightmare, and Python multiprocessing is designed to
    ## prevent that, so for now we are using multiprocessing in this code. If
    ## it turns out to be too much of a memory drain, we can rewrite this the
    ## hard way.
    ##
    ## The following architecture is used to work with these difficulties:
    ##
    ## * Each thread has three file descriptors it watches via epoll by
    ##   default; a termiante read fd, a notify read fd, and the read fd of the
    ##   session the thread handles.
    ## * For receiving notifications from other threads, a notify queue is
    ##   provided. This can be used for both internal communication and message
    ##   broadcasts. When used for broadcasting messages, the messages in the
    ##   queue are expected to be sent unmodified, in order, at some point,
    ##   after checking if they are appropriate to send. Correlation IDs avert
    ##   any problems with this kind of multiplexing.
    ## * Any session thread can write into any other session thread's notify
    ##   write pipe and notification queue without locking (Python handles any
    ##   needed locking for us here). However, when iterating through the list
    ##   of sessions, each session thread MUST lock
    ##   SandboxdGlobal.session_list_lock to avoid racing the main thread.
    ## * For specific "trivial" situations, we handle messages synchronously in
    ##   this thread. Examples include handling very trivial messages (i.e.
    ##   QUERY_NEED_RESTART), permissions handling, and letting clients know
    ##   that a long-running process has started.
    ## * Most other messages trigger a new handler process to be spawned via
    ##   multiprocessing. This process communicates to the parent using a pipe
    ##   so that epoll can be used to wake up the thread when the handler has
    ##   something to say.
    ## * Handler processes never communicate with clients directly, they
    ##   always go through this thread to do that. All messages sent back by
    ##   handlers are messages that are intended to be forwarded to clients.
    ##   The only messages expected to be sent to handler processes are
    ##   messages received from the client.
    ## * Each handler has a message correlation ID associated with it.
    ##   Incoming messages that have a correlation ID matching a running
    ##   handler are blindly forwarded to that handler; it is the handler's
    ##   responsibility to handle invalid messages correctly.
    ## * Handlers ALWAYS run with the same privileges as sandboxd itself. We
    ##   do NOT spawn handlers inside the sandbox, because multiprocessing
    ##   pipes use Python's pickle serialization format internally, which
    ##   presents a security risk.
    ## * The only messages that are not handled by typical handler processes
    ##   or by sandboxd directly are the "boot" commands. These are handled by
    ##   NspawnManager processes instead, since they are not specific to any
    ##   one client and need to persist after clients disconnect. The objects
    ##   send between an NspawnManager and sandboxd are NOT intended to be
    ##   blindly forwarded, the protocol here is custom.

    def __init__(self, comm_session: SmdSession) -> None:
        ## Notification pipe used to tell this thread when to shut down.
        self.terminate_read_fd: int
        self.terminate_write_fd: int
        self.terminate_read_fd, self.terminate_write_fd = os.pipe()
        self.terminate_read_pipe: IO[bytes] = os.fdopen(
            self.terminate_read_fd, "rb", buffering=0
        )
        self.terminate_write_pipe: IO[bytes] = os.fdopen(
            self.terminate_write_fd, "wb", buffering=0
        )

        ## Notification pipe and queue used for broadcast messages.
        self.notify_read_fd: int
        self.notify_write_fd: int
        self.notify_read_fd, self.notify_write_fd = os.pipe()
        self.notify_read_pipe: IO[bytes] = os.fdopen(
            self.notify_read_fd, "rb", buffering=0
        )
        self.notify_write_pipe: IO[bytes] = os.fdopen(
            self.notify_write_fd, "wb", buffering=0
        )
        self.notify_queue: SimpleQueue[
            SmdBaseMsg | SandboxdCommThreadShutdown
        ] = SimpleQueue()

        ## The underlying connection to the client.
        self.comm_session = comm_session

        ## Whether the client should have broadcast messages sent to it.
        self.client_is_long_running: bool = False

        ## Actively running handler processes.
        self.handler_list: list[HandlerProc] = []

        ## A list of threads we can broadcast config messages to.
        self.config_broadcast_thread_list: list[SandboxdCommThread] = []

        ## Specifies which functions correlate to which client-sent messages.
        self.message_handler_map: dict[
            type[SmdBaseMsg], Callable[[SmdCommClientMsg], None]
        ] = {
            SmdCommClientSyncMsg: self.client_sync_handler,
            SmdCommClientQueryNeedRestartMsg: self.client_query_need_restart,
            ## TODO: add more handlers here
        }

        self.internal_thread: Thread = Thread(
            target=self.thread_main_loop, daemon=True
        )
        self.internal_thread.start()

    ## A lot of this code has to call 'break', making it difficult to break
    ## into separate functions without making readability worse.
    # pylint: disable=too-many-branches, too-many-statements
    def thread_main_loop(self) -> None:
        """
        The thread's main function.
        """

        assert self.comm_session.server_socket_fileno != -1
        epoll_obj: select.epoll = select.epoll()
        epoll_obj.register(self.terminate_read_fd, select.EPOLLIN)
        epoll_obj.register(self.notify_read_fd, select.EPOLLIN)
        epoll_obj.register(
            self.comm_session.server_socket_fileno, select.EPOLLIN
        )

        while True:
            epoll_event_fd_list: list[int] = [x[0] for x in epoll_obj.poll()]
            if self.terminate_read_fd in epoll_event_fd_list:
                break

            if self.notify_read_fd in epoll_event_fd_list:
                self.notify_read_pipe.read(1)
                notify_obj: SmdBaseMsg | SandboxdCommThreadShutdown = (
                    self.notify_queue.get()
                )
                if isinstance(notify_obj, SmdBaseMsg):
                    try:
                        self.comm_session.send_msg(notify_obj)
                    except Exception as e:
                        logging.error(
                            "Could not send '%s'", notify_obj.name, exc_info=e
                        )
                        break
                else:  ## isinstance(notify_obj, SandboxdCommThreadShutdown)
                    if (
                        notify_obj.shutdown_thread
                        in self.config_broadcast_thread_list
                    ):
                        self.config_broadcast_thread_list.remove(
                            notify_obj.shutdown_thread
                        )
                epoll_event_fd_list.remove(self.notify_read_fd)

            if self.comm_session.server_socket_fileno in epoll_event_fd_list:
                try:
                    self.handle_incoming_message()
                except Exception as e:
                    logging.error(
                        "Could not handle message from client", exc_info=e
                    )
                    break
                epoll_event_fd_list.remove(
                    self.comm_session.server_socket_fileno
                )

            ## All remaining file descriptors are child processes trying to
            ## send something to a client, handle accordingly
            for handler_pipe_fd in epoll_event_fd_list:
                source_handler: HandlerProc | None = None
                for candidate_handler in self.handler_list:
                    if candidate_handler.ctp_pipe.fileno() == handler_pipe_fd:
                        source_handler = candidate_handler
                        break
                if source_handler is None:
                    logging.critical(
                        "sandboxd lost track of a handler process!"
                    )
                    sys.exit(1)
                try:
                    recv_obj: Any = source_handler.ctp_pipe.recv()
                except EOFError:
                    ## Handler terminated, clean it up
                    self.handler_list.remove(source_handler)
                    continue
                assert isinstance(recv_obj, (SmdCommServerMsg, SmdCommBidiMsg))
                msg_from_child: SmdCommServerMsg | SmdCommBidiMsg = recv_obj
                try:
                    self.comm_session.send_msg(msg_from_child)
                except Exception as e:
                    logging.error(
                        "Could not send '%s'", msg_from_child.name, exc_info=e
                    )
                    break
                self.broadcast_message_maybe(msg_from_child)

        ## Close the I/O pipes for all handlers so that they can cleanly
        ## terminate, rather than killing them manually.
        for single_handler in self.handler_list:
            single_handler.ptc_pipe.close()
        self.handler_list.clear()

        ## Notify all other threads that this thread is shutting down so they
        ## can perform any needed cleanup.
        with SandboxdGlobal.session_list_lock:
            for comm_thread in SandboxdGlobal.comm_thread_list:
                comm_thread.notify_queue.put(SandboxdCommThreadShutdown(self))
                while comm_thread.notify_write_pipe.write(b"\x00") == 0:
                    pass

    def handle_incoming_message(self) -> None:
        """
        Reads an incoming message, and dispatches it to a handler function.
        """

        client_msg: SmdBaseMsg = self.comm_session.get_msg()
        if type(client_msg) not in self.message_handler_map:
            raise ConnectionError(
                f"No handler for message type '{str(type(client_msg))}'"
            )
        assert isinstance(client_msg, SmdCommClientMsg)
        handler_func: Callable[[SmdCommClientMsg], None] = (
            self.message_handler_map[type(client_msg)]
        )
        handler_func(client_msg)

    def broadcast_message_maybe(
        self, msg_to_send: SmdCommServerMsg | SmdCommBidiMsg
    ) -> None:
        """
        Checks if a message should be broadcast to some or all connected
        clients. Sends it to (and wakes up) relevant client threads if needed.
        """

        if isinstance(msg_to_send, SmdCommServerRestartInprogressMsg):
            with SandboxdGlobal.session_list_lock:
                for comm_thread in SandboxdGlobal.comm_thread_list:
                    comm_thread.notify_queue.put(msg_to_send)
                    while comm_thread.notify_write_pipe.write(b"\x00") == 0:
                        pass
        elif (
            isinstance(msg_to_send, SmdCommBidiMsg) or msg_to_send.do_broadcast
        ):
            with SandboxdGlobal.session_list_lock:
                for comm_thread in SandboxdGlobal.comm_thread_list:
                    if (
                        comm_thread.comm_session.user_name
                        != self.comm_session.user_name
                    ):
                        continue
                    if not comm_thread.client_is_long_running:
                        continue

                    if isinstance(
                        msg_to_send,
                        (
                            SmdCommServerCreateInprogressMsg,
                            SmdCommServerConfigInprogressMsg,
                            SmdCommServerCreateSuccessMsg,
                            SmdCommServerCreateFailedMsg,
                            SmdCommServerConfigSuccessMsg,
                            SmdCommServerConfigFailedMsg,
                        ),
                    ):
                        self.config_broadcast_thread_list.append(comm_thread)
                    elif isinstance(
                        msg_to_send,
                        (
                            SmdCommBidiMsg,
                            SmdCommServerConfigInfoStartMsg,
                            SmdCommServerConfigInfoEndMsg,
                        ),
                    ):
                        if comm_thread not in self.config_broadcast_thread_list:
                            continue

                    comm_thread.notify_queue.put(msg_to_send)
                    while comm_thread.notify_write_pipe.write(b"\x00") == 0:
                        pass

    def client_sync_handler(self, client_msg: SmdCommClientMsg) -> None:
        """
        Handles SYNC messages.
        """

        ## WARNING: This function MUST be implemented in a synchronous
        ## fashion. We need to send the state of sandboxes on the system at
        ## the time this function was called, accumulating any state changes
        ## in the notify queue. This prevents the client from receiving partial
        ## state information if started in the middle of other activity.

        assert isinstance(client_msg, SmdCommClientSyncMsg)

    def client_query_need_restart(self, client_msg: SmdCommClientMsg) -> None:
        """
        Handles QUERY_NEED_RESTART messages.
        """

        assert isinstance(client_msg, SmdCommClientQueryNeedRestartMsg)
        ## TODO

    ## TODO: add more handlers here

    def terminate(self) -> None:
        """
        Tells the thread to shut down. Note that any thread can call this.
        """

        try:
            while self.terminate_write_pipe.write(b"\x00") == 0:
                pass
        except Exception:
            pass


def ensure_running_as_root() -> None:
    """
    Ensures the server is running as root.
    """

    if os.geteuid() != 0:
        logging.critical("sandboxd must run as root!")
        sys.exit(1)


def verify_not_running_twice() -> None:
    """
    Ensures that two simultaneous instances of sandboxd are not running at the
    same time. Note that this only prevents common mistakes, this function can
    be fooled by launching two sandboxd processes at the same time (as
    opposed to starting a new one when one is already fully running).
    """

    if not SandboxdGlobal.pid_file_path.exists():
        return

    with open(SandboxdGlobal.pid_file_path, "r", encoding="utf-8") as pid_file:
        old_pid_str: str = pid_file.read().strip()
        try:
            old_pid: int = int(old_pid_str)
        except Exception:
            return

        # Send signal 0 to check for existence, this will raise an OSError if
        # the process doesn't exist
        try:
            os.kill(old_pid, 0)
            # If no exception, the old sandboxd process is still running.
            logging.critical(
                "Cannot run two sandboxd processes at the same time!"
            )
            sys.exit(1)
        except OSError:
            return
        except Exception as e:
            logging.critical(
                "Could not check for simultaneously running sandboxd "
                "processes!",
                exc_info=e,
            )
            sys.exit(1)


def cleanup_old_state_dir() -> None:
    """
    Cleans up the old state directory left behind by a previous sandboxd
    instance.
    """

    # This probably won't run anywhere but Linux, but just in case, make sure
    # we aren't opening a security hole
    if not shutil.rmtree.avoids_symlink_attacks:
        logging.critical(
            "This platform does not allow recursive deletion of a directory "
            "without a symlink attack vuln!"
        )
        sys.exit(1)
    # Cleanup any sockets left behind by an old sandboxd process
    if SmdCommon.state_dir.exists():
        try:
            shutil.rmtree(SmdCommon.state_dir)
        except Exception as e:
            logging.critical(
                "Could not delete '%s'!",
                str(SmdCommon.state_dir),
                exc_info=e,
            )
            sys.exit(1)


def populate_state_dir() -> None:
    """
    Creates the state dir and PID file.
    """

    if not SmdCommon.state_dir.exists():
        try:
            SmdCommon.state_dir.mkdir(parents=True)
            SmdCommon.state_dir.chmod(0o755)
        except Exception as e:
            logging.critical(
                "Cannot create '%s'!",
                str(SmdCommon.state_dir),
                exc_info=e,
            )
            sys.exit(1)
    else:
        logging.critical(
            "Directory '%s' should not exist yet, but does!",
            str(SmdCommon.state_dir),
        )
        sys.exit(1)

    if not SmdCommon.comm_dir.exists():
        try:
            SmdCommon.comm_dir.mkdir(parents=True)
            SmdCommon.comm_dir.chmod(0o755)
        except Exception as e:
            logging.critical(
                "Cannot create '%s'!",
                str(SmdCommon.comm_dir),
                exc_info=e,
            )
            sys.exit(1)
    else:
        logging.critical(
            "Directory '%s' should not exist yet, but does!",
            str(SmdCommon.comm_dir),
        )
        sys.exit(1)

    try:
        with open(
            SandboxdGlobal.pid_file_path, "w", encoding="utf-8"
        ) as pid_file:
            pid_file.write(str(os.getpid()) + "\n")
        SandboxdGlobal.pid_file_path.chmod(0o644)
    except Exception as e:
        logging.critical(
            "Cannot create PID file at '%s'!",
            str(SandboxdGlobal.pid_file_path),
            exc_info=e,
        )
        sys.exit(1)


def open_control_socket() -> None:
    """
    Opens the control socket. Sandboxd clients can connect to this socket to
    request that sandboxd create or destroy comm sockets used for
    communicating with unprivileged users.
    """

    try:
        control_socket: SmdServerSocket = SmdServerSocket(SmdSocketType.CONTROL)
    except Exception as e:
        logging.critical("Failed to open control socket!", exc_info=e)
        sys.exit(1)

    SandboxdGlobal.socket_list.append(control_socket)


def prepare_sandbox_dir() -> None:
    """
    Ensures the sandbox dir exists, is a directory, and has the correct
    ownership and permissions.
    """

    if not SmdCommon.sandbox_dir.exists():
        try:
            SmdCommon.sandbox_dir.mkdir(parents=True)
        except Exception as e:
            logging.critical(
                "Sandbox dir '%s' does not exist and cannot be created!",
                SmdCommon.sandbox_dir,
                exc_info=e
            )
            sys.exit(1)
    elif not SmdCommon.sandbox_dir.is_dir():
        logging.critical(
            "Sandbox dir '%s' exists but is not a directory!",
            SmdCommon.sandbox_dir,
        )

    stat_info: os.stat_result = os.stat(SmdCommon.sandbox_dir)
    if stat_info.st_uid != 0:
        logging.critical(
            "Sandbox dir '%s' exists but is owned by UID %s instead of UID 0!",
            SmdCommon.sandbox_dir,
            stat_info.st_uid,
        )
        sys.exit(1)
    if stat_info.st_gid != 0:
        logging.critical(
            "Sandbox dir '%s' exists but is owned by GID %s instead of GID 0!",
            SmdCommon.sandbox_dir,
            stat_info.st_uid,
        )
        sys.exit(1)
    dir_mode: int = stat_info.st_mode & 0x777
    if dir_mode != 0o700:
        logging.critical(
            "Sandbox dir '%s' exists but has permissions %s rather than "
            + "permissions 0o755!",
            SmdCommon.sandbox_dir,
            dir_mode
        )
        sys.exit(1)


def validate_sandbox_repo() -> None:
    """
    Validates that all sandboxes directories have expected contents.
    """

    for sandbox_user_path in SmdCommon.sandbox_dir.iterdir():
        try:
            SmdCommon.validate_id(
                sandbox_user_path.name,
                [SmdValidateType.USER_UID],
                "Sandbox user dir name is not a UID",
            )
        except ValueError as e:
            logging.critical(
                "Invalid sandbox user dir '%s'!",
                sandbox_user_path,
                exc_info=e,
            )
            sys.exit(1)

        if not sandbox_user_path.is_dir():
            logging.critical(
                "'%s' is not a directory, but should be a sandbox user "
                + "directory!",
                sandbox_user_path,
            )
            sys.exit(1)

        for sandbox_path in sandbox_user_path.iterdir():
            try:
                SmdCommon.validate_id(
                    sandbox_path.name,
                    [SmdValidateType.UUID],
                    "Sandbox name is not a UUID",
                )
            except ValueError as e:
                logging.critical(
                    "Invalid sandbox dir '%s'!",
                    sandbox_path,
                    exc_info=e,
                )

            if not sandbox_path.is_dir():
                logging.critical(
                    "'%s' is not a directory, but should be a sandbox "
                    + "directory!",
                    sandbox_path,
                )
                sys.exit(1)

            for file_type, file_path in [
                ("root", Path(sandbox_path, SmdCommon.sandbox_root_file)),
                ("data", Path(sandbox_path, SmdCommon.sandbox_data_file)),
                ("config", Path(sandbox_path, SmdCommon.sandbox_config_file)),
            ]:
                if not file_path.is_file():
                    logging.critical(
                        "Sandbox %s file '%s' does not exist or is not a "
                        + "file!",
                        file_type,
                        file_path,
                    )
                    sys.exit(1)


def load_sandbox_config() -> None:
    """
    Loads the configuration files for all sandboxes.
    """

    for sandbox_user_path in SmdCommon.sandbox_dir.iterdir():
        for sandbox_path in sandbox_user_path.iterdir():
            config_path: Path = Path(
                sandbox_path, SmdCommon.sandbox_config_file
            )
            try:
                config_dict: dict[str, Any] = (
                    strict_config_parser.parse_config_files(
                        conf_item_list=[str(config_path)],
                        conf_schema=SandboxdGlobal.conf_schema,
                    )
                )
            except Exception as e:
                logging.critical(
                    "Could not load config file '%s'!", config_path, exc_info=e
                )
                sys.exit(1)

            ## All the asserts here are just to make mypy happy.
            assert isinstance(config_dict["name"], str)
            assert isinstance(config_dict["description"], str)
            assert isinstance(config_dict["root_vol_size"], int)
            assert isinstance(config_dict["data_vol_size"], int)
            assert isinstance(config_dict["memory"], int)
            assert isinstance(config_dict["cpu_weight"], int)
            #assert isinstance(config_dict["cpu_cores"], int)
            assert isinstance(config_dict["io_weight"], int)
            assert isinstance(config_dict["audio_enabled"], bool)
            assert isinstance(config_dict["wayland_enabled"], bool)
            assert isinstance(config_dict["x11_enabled"], bool)
            assert isinstance(config_dict["three_d_enabled"], bool)
            assert isinstance(config_dict["network_enabled"], bool)
            assert isinstance(config_dict["nested_sandboxing_enabled"], bool)
            assert isinstance(config_dict["shared_fso_list"], list)
            assert isinstance(config_dict["shared_device_list"], list)
            assert all(
                isinstance(x, str) for x in config_dict["shared_device_list"]
            )

            shared_fso_list: list[SharedFsoConfig] = []
            for shared_fso_blob in config_dict["shared_fso_list"]:
                assert isinstance(shared_fso_blob["read_write"], bool)
                assert isinstance(shared_fso_blob["host_path"], str)
                assert isinstance(shared_fso_blob["sandbox_path"], str)
                shared_fso_list.append(
                    SharedFsoConfig(
                        shared_fso_blob["read_write"],
                        shared_fso_blob["host_path"],
                        shared_fso_blob["sandbox_path"],
                    )
                )

            SandboxdGlobal.sandbox_config_list.append(
                SandboxConfig(
                    uuid=sandbox_path.name,
                    user_uid=int(sandbox_user_path.name),
                    name=config_dict["name"],
                    description=config_dict["description"],
                    root_vol_size=config_dict["root_vol_size"],
                    data_vol_size=config_dict["data_vol_size"],
                    memory=config_dict["memory"],
                    cpu_weight=config_dict["cpu_weight"],
                    #cpu_cores=config_dict["cpu_cores"],
                    io_weight=config_dict["io_weight"],
                    audio_enabled=config_dict["audio_enabled"],
                    wayland_enabled=config_dict["wayland_enabled"],
                    x11_enabled=config_dict["x11_enabled"],
                    three_d_enabled=config_dict["three_d_enabled"],
                    network_enabled=config_dict["network_enabled"],
                    nested_sandboxing_enabled=config_dict[
                        "nested_sandboxing_enabled"
                    ],
                    shared_fso_list=shared_fso_list,
                    shared_device_list=config_dict["shared_device_list"],
                )
            )


def prep_sock_notify_pipe() -> None:
    """
    Prepares a pipe fd pair used to inform the main thread when a new socket
    is about to be added or removed.
    """

    SandboxdGlobal.ctm_read_fd, SandboxdGlobal.ctm_write_fd = os.pipe()
    SandboxdGlobal.ctm_read_pipe = os.fdopen(
        SandboxdGlobal.ctm_read_fd, "rb", buffering=0
    )
    SandboxdGlobal.ctm_write_pipe = os.fdopen(
        SandboxdGlobal.ctm_write_fd, "wb", buffering=0
    )


def send_control_msg_safe(session: SmdSession, msg: SmdBaseMsg) -> None:
    """
    Sends a message, logging an error and otherwise ignoring the issue if the
    message cannot be sent. This is only intended for use by the control
    thread, as comm threads will care a lot if sending a message fails and
    should be doing exception handling themselves.
    """

    try:
        session.send_msg(msg)
    except Exception as e:
        logging.error("Could not send '%s'", msg.name, exc_info=e)


def handle_control_register_msg(
    control_session: SmdSession, control_msg: SmdControlClientRegisterMsg
) -> None:
    """
    Handles a REGISTER control message from the client.
    """

    orig_user_name: str = control_msg.arg_list[0]
    user_name: str | None = SmdCommon.normalize_user_id(orig_user_name)
    if user_name is None:
        logging.warning("Account '%s' does not exist", orig_user_name)
        send_control_msg_safe(
            control_session,
            SmdControlServerRegisterFailureMsg(control_msg.correlation_id),
        )
        return

    for server_sock in SandboxdGlobal.socket_list:
        if server_sock.user_name == user_name:
            logging.info(
                "Handled REGISTER message for account '%s', socket already "
                + "exists",
                user_name,
            )
            send_control_msg_safe(
                control_session,
                SmdControlServerRegisterExistsMsg(control_msg.correlation_id),
            )
            return

    try:
        comm_socket: SmdServerSocket = SmdServerSocket(
            SmdSocketType.COMMUNICATION, user_name
        )
        SandboxdGlobal.add_control_socket_queue.put(comm_socket)
        assert SandboxdGlobal.ctm_write_pipe is not None
        while SandboxdGlobal.ctm_write_pipe.write(b"\x00") == 0:
            pass
        logging.info(
            "Handled REGISTER message for account '%s', socket created",
            user_name,
        )
        send_control_msg_safe(
            control_session,
            SmdControlServerRegisterSuccessMsg(control_msg.correlation_id),
        )
        return
    except Exception as e:
        logging.error(
            "Failed to create socket for account '%s'!", user_name, exc_info=e
        )
        send_control_msg_safe(
            control_session,
            SmdControlServerRegisterFailureMsg(control_msg.correlation_id),
        )
        return


def handle_control_unregister_msg(
    control_session: SmdSession, control_msg: SmdControlClientRegisterMsg
) -> None:
    """
    Handles an UNREGISTER control message from the client.
    """

    ## We don't require the username to pass validation here since we only
    ## create sockets for users after validation passes. We do still normalize
    ## the user ID to support passing a UID here.

    orig_user_name: str = control_msg.arg_list[0]
    user_name: str | None = SmdCommon.normalize_user_id(orig_user_name)
    if user_name is None:
        user_name = orig_user_name

    for server_sock in SandboxdGlobal.socket_list:
        if server_sock.user_name is None:
            continue
        if server_sock.user_name == user_name:
            try:
                server_sock.close()
                SandboxdGlobal.remove_control_socket_queue.put(server_sock)
                assert SandboxdGlobal.ctm_write_pipe is not None
                while SandboxdGlobal.ctm_write_pipe.write(b"\x00") == 0:
                    pass
                logging.info(
                    "Handled UNREGISTER message for account '%s', socket "
                    + "destroyed",
                    user_name,
                )
                send_control_msg_safe(
                    control_session,
                    SmdControlServerUnregisterSuccessMsg(
                        control_msg.correlation_id
                    ),
                )
                return
            except Exception as e:
                logging.error(
                    "Failed to destroy socket for account '%s'!",
                    user_name,
                    exc_info=e,
                )
                send_control_msg_safe(
                    control_session,
                    SmdControlServerUnregisterFailureMsg(
                        control_msg.correlation_id
                    ),
                )
                return

    logging.info(
        "Handled UNREGISTER message for account '%s', socket did not exist",
        user_name,
    )
    send_control_msg_safe(
        control_session,
        SmdControlServerUnregisterAbsentMsg(control_msg.correlation_id),
    )


def control_handler_loop() -> NoReturn:
    """
    Control connection handler thread. This waits for new control requests to
    be passed to it over a queue, and handles them as they show up. This
    prevents control connections from hanging up normal operation of sandboxd.
    """

    while True:
        control_session: SmdSession = SandboxdGlobal.control_session_queue.get()

    try:
        try:
            control_msg: SmdBaseMsg = control_session.get_msg()
        except Exception as e:
            logging.error(
                "Could not get message from control client!", exc_info=e
            )
            return

        if isinstance(control_msg, SmdControlClientRegisterMsg):
            handle_control_register_msg(control_session, control_msg)
        elif isinstance(control_msg, SmdControlClientUnregisterMsg):
            handle_control_unregister_msg(control_session, control_msg)
        else:
            logging.critical(
                "sandboxd mis-parsed a control command from the client!"
            )
            sys.exit(1)
    finally:
        control_session.close_session()


def handle_control_socket_conn(control_socket: SmdServerSocket) -> None:
    """
    Handles control socket connections, for creating or destroying comm
    sockets. See control_handler_loop for most of the real logic this
    triggers.
    """

    try:
        control_session: SmdSession = control_socket.get_session()
    except Exception as e:
        logging.error(
            "Could not start control session with client!", exc_info=e
        )
        return

    SandboxdGlobal.control_session_queue.put(control_session)


def handle_comm_socket_conn(comm_socket: SmdServerSocket) -> None:
    """
    Handles comm socket connections.
    """

    try:
        comm_session: SmdSession = comm_socket.get_session()
    except Exception as e:
        logging.error(
            "Could not start comm session with client run by account '%s'!",
            comm_socket.user_name,
            exc_info=e,
        )
        return

    SandboxdGlobal.comm_thread_list.append(SandboxdCommThread(comm_session))


def main_loop() -> NoReturn:
    """
    Watches for and accepts connections and disconnection notices, spawning and
    dispatching to threads to handle most work.
    """

    assert SandboxdGlobal.ctm_read_pipe is not None
    epoll_fd_set: set[int] = set()
    epoll_obj: select.epoll = select.epoll()
    epoll_obj.register(SandboxdGlobal.ctm_read_fd, select.EPOLLIN)
    server_socket_change: bool = True

    while True:
        if server_socket_change:
            while True:
                try:
                    new_sock: SmdServerSocket = (
                        SandboxdGlobal.add_control_socket_queue.get_nowait()
                    )
                except queue.Empty:
                    break
                SandboxdGlobal.socket_list.append(new_sock)
            while True:
                try:
                    remove_sock: SmdServerSocket = (
                        SandboxdGlobal.remove_control_socket_queue.get_nowait()
                    )
                except queue.Empty:
                    break
                ## We probably could use a filter here, but we have to call the
                ## terminate() method of any threads we remove, necessitating
                ## an ugly loop.
                ##
                ## No 'with' to avoid indenting this already over-indented
                ## block even further. This should be split into its own
                ## function at some point.
                # pylint: disable=consider-using-with
                SandboxdGlobal.session_list_lock.acquire()
                thread_ctr: int = 0
                while thread_ctr < len(SandboxdGlobal.comm_thread_list):
                    target_thread: SandboxdCommThread = (
                        SandboxdGlobal.comm_thread_list[thread_ctr]
                    )
                    if (
                        target_thread.comm_session.server_socket_fileno
                        == remove_sock.fileno()
                    ):
                        target_thread.terminate()
                        SandboxdGlobal.comm_thread_list.pop(thread_ctr)
                        continue
                    thread_ctr += 1
                SandboxdGlobal.session_list_lock.release()
                SandboxdGlobal.socket_list.remove(remove_sock)
            read_sock_fileno_list: list[int] = [
                sock_obj.fileno() for sock_obj in SandboxdGlobal.socket_list
            ]
            read_sock_fileno_set: set[int] = set(read_sock_fileno_list)
            for register_fileno in read_sock_fileno_set - epoll_fd_set:
                epoll_obj.register(register_fileno, select.EPOLLIN)
            epoll_fd_set.update(read_sock_fileno_set)
            for remove_fileno in epoll_fd_set - read_sock_fileno_set:
                epoll_fd_set.remove(remove_fileno)
            server_socket_change = False

        epoll_event_fd_list: list[int] = [x[0] for x in epoll_obj.poll(5)]
        SandboxdGlobal.sdnotify_object.notify("WATCHDOG=1")

        if SandboxdGlobal.ctm_read_fd in epoll_event_fd_list:
            ## Connection change, i.e. adding or removing a socket. The main
            ## thread needs to synchronize with the control thread when this
            ## is done to prevent losing track of or not noticing a new
            ## socket.
            SandboxdGlobal.ctm_read_pipe.read(1)
            server_socket_change = True
            continue

        ## Note that if we get this far, SandboxdGlobal.ctm_read_fd is NOT in
        ## epoll_event_fd_list, so we don't need to check for its presence and
        ## can assume all fds correspond to active sockets.
        for ready_sock_fileno in epoll_event_fd_list:
            ready_sock_obj: SmdServerSocket | None = None
            for sock_obj in SandboxdGlobal.socket_list:
                if sock_obj.fileno() == ready_sock_fileno:
                    ready_sock_obj = sock_obj
                    break
            if ready_sock_obj is None:
                logging.critical("sandboxd lost track of a socket!")
                sys.exit(1)
            if ready_sock_obj.socket_type == SmdSocketType.CONTROL:
                handle_control_socket_conn(ready_sock_obj)
            else:
                handle_comm_socket_conn(ready_sock_obj)


def main() -> NoReturn:
    """
    Main thread entry point.
    """

    ## Set restrictive umask to prevent any file permission vulnerability
    ## window during socket creation, this denies all privileges for
    ## non-owners.
    SandboxdGlobal.old_umask = os.umask(0o077)

    ## Use the 'spawn' method for starting new processes with multiprocessing,
    ## since 'fork' can cause problems, especially with multithreaded code like
    ## this.
    ##
    ## TODO: Consider using 'forkserver' here instead, if it works and is safe
    ## it may be faster.
    mp.set_start_method("spawn")

    logging.basicConfig(
        format="%(funcName)s: %(levelname)s: %(message)s", level=logging.INFO
    )

    ensure_running_as_root()
    verify_not_running_twice()
    cleanup_old_state_dir()
    populate_state_dir()
    prepare_sandbox_dir()
    validate_sandbox_repo()
    load_sandbox_config()
    open_control_socket()
    prep_sock_notify_pipe()
    control_handler_thread: Thread = Thread(
        target=control_handler_loop, daemon=True
    )
    control_handler_thread.start()
    SandboxdGlobal.sdnotify_object.notify("READY=1")
    SandboxdGlobal.sdnotify_object.notify("STATUS=Fully started")
    main_loop()
