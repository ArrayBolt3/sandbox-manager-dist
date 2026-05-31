# What's the goal for this to be a minimal viable product?

Ultimately, we need it to be very easy and comfortable to use Tor Browser
sandboxed. Users need to be able to run Tor Browser in a sandbox, interact
with it the same way they'd interact with an unsandboxed browser, make files
available to it, move files downloaded with it out of the sandbox, keep it
updated properly, launch it from the Start Menu, etc., without any difficulty.

Beyond that, we want this to become usable for general purpose, Android-like
app sandboxing. Users should not *have* to mess with permissions in order to
get apps working. Users should not *have* to mess with manual software
installation and the management of sandboxes if they don't want to. Users
should be able to just install an app and *use* it. We're not going to be able
to get a UX as smooth as Android simply because Linux applications are not
(always) designed to be super smooth and easy to use sandboxed like Android
applications, and the tools that do allow ease-of-use for sandboxed
applications are less secure than would be hoped. (In particular
xdg-desktop-portal has an architectural flaw in it that will likely prevent it
from being safe to use for a long time.)

Beyond the semi-obvious features we need (mapped out in the design below),
we'll need to do some special things to get the sandbox to work properly with
our existing tb-updater system. That means we'll need to:

* Continue providing Tor Browser the same way we always have, and continue
  supporting running it directly on the host OS.
* It can optionally be bind-mounted into a sandbox and launched there instead.
  (We will also have to bind-mount in UNIX sockets that allow for Tor
  connectivity with stream isolation.)
* In a perfect world we would ship a sandbox by default, however this would
  greatly increase the disk space required by Whonix-Workstation, which may be
  a problem.
  * Need to ascertain how much disk space is taken up by this, maybe it won't
    be that bad?
* It's hard to generalize this in a particularly useful way; we could add a
  feature that allows setting up a specific, mostly self-contained app in a
  sandbox?
  * Might not be a niche feature, lots of apps are shipped as tarballs or
    AppImages.
  * The user would still need to know where Tor Browser is, which may be
    difficult.
* Maybe best to create a start menu entry for "Set up Sandboxed Tor Browser"
  that will do everything for the user?

For the "app store" experience described above, we can use browser-choice to
implement something like this fairly easily. A user can just select the app
they want to install, the installer will set up a new sandbox and install the
app in it, then pin it to the Start Menu. The user will then be able to access
it normally.

# Misc design considerations

* While it would be simpler to implement most of this synchronously, we should
  probably go with an asynchronous design as much as possible. Synchronous
  execution is simple in the short term, but it's technical debt we'll
  potentially end up having to work around in the long term, and refactoring
  something synchronous to work asynchronously is a major challenge.
* The protocol needs to act somewhat like Wayland, where we send applicable
  state information to the client almost immediately upon connection. The
  client then tells the backend to make various changes, and waits to update
  its local state until the backend sends information about a state update.
* The server **WILL** be sending state updates we don't expect. This is
  necessary to allow changes made by the CLI to update the GUI.
* We probably will not be able to make the GUI simply a frontend to the CLI.
  We need a direct, persistent, and live-monitored connection for this to
  work.
* We should cache sandbox images, otherwise users will end up building lots of
  images and wasting lots of network bandwidth. sbuild handles caching by
  creating an image on-demand, then keeping it around for some time (a week?).
  Any time it's needed before it expires, it's used as-is, after that it is
  rebuilt from scratch. We can probably do something similar here.
* The sandboxes will be running Kicksecure, not vanilla Debian (I thought
  there was some reason to avoid doing this but I can't recall it now).
* We might want to use derivative-maker to build the sandbox images, but
  that's somewhat scary because there is a lot that can go wrong when running
  derivative-maker. It would be easier to make a small custom builder that
  would simply bootstrap a Debian image and then distribution-morph it to
  Kicksecure.

# Notes on getting various components to behave

* systemd-nspawn
  * Restricting user namespaces via a system call filter or similar is
    non-ideal because the clone3 system call has to be entirely disabled.
    However, `/proc/sys/user/max_user_namespaces` can be set to 0, which
    appears to turn user namespaces off within the container.
  * Do NOT expect `--network-veth` to work out of the box, it's supposed to but
    it doesn't. It's probably possible to get it working, but in the short
    term, simply leaving network namespaces out of the picture is a relatively
    simple solution. I don't think we need a network namespace if we're
    allowing an application to access the network.
  * Make sure to use idmapped bind mounts to get file ownership to make sense.
    `--bind=/tmp/.X11-unix:/tmp/.X11-unix:idmap` works quite well for this
    purpose.
* mmdebstrap
  * `sudo mmdebstrap --format=ext4 trixie trixie.img` will spin up an ext4
    filesystem image with Trixie installed into it. Grow the image with
    `sudo truncate --size=2G trixie.img && sudo resize2fs trixie.img`.

# GUI flow:

## Home screen

```
+-----------------------------------------------------------------------------------+
| @ Sandbox Manager                                                           v ^ X |
+-----------------------------------------------------------------------------------+
| >Home<         | Get started with Sandbox Manager                                 |
| <Sandboxes>    |                                                                  |
| <Applications> | Switch between "Home", "Sandboxes", and "Applications" views     |
| <Logs>         | using the toolbar on the left.                                   |
|                |                                                                  |
|                | Create, configure, boot, and delete sandboxes in the "Sandboxes" |
|                | view.                                                            |
|                |                                                                  |
|                | Launch applications and pin them to the Start Menu in the        |
|                | "Applications" view.                                             |
|                |                                                                  |
| <Running Jobs> | More documentation is available on the sandbox-manager-dist      |
| {------------} | page on the Kicksecure Wiki.                                     |
+-----------------------------------------------------------------------------------+
```

* When "Home" is clicked on this or any other screen, switches to the Home
  screen.
* When "Sandboxes" is clicked on this or any other screen, switches to the
  appropriate variant of the Sandboxes screen.
* When "Applications" is clicked on this or any other screen, switches to the
  appropriate variant of the Applications screen.
* When "Logs" is clicked on this or any other screen, switches to the Logs
  screen.
* When "Running Jobs" is clicked on this or any other screen, opens the
  Running Jobs screen in a new window.
* If the user attempts to close the window when a data transfer job is
  present, opens the Data Transfer Incomplete screen in a new window.
* If the connection between the frontend and backend breaks, opens the
  Connection Lost screen in a new window.
* If the backend sends an invalid message, opens the Backend Bug screen in a
  new window.
* If the backend is outdated when the frontend is opened, opens the Restart
  Backend screen in a new window.
* If damaged sandboxes are found when the frontend is opened, opens the Damaged
  Sandboxes screen in a new window.

## Sandboxes screen (normal mode)

If no sandboxes exist:

```
* All buttons in the top bar except for "Create" are grayed out.

+-----------------------------------------------------------------------------------+
| @ Sandbox Manager                                                           v ^ X |
+-----------------------------------------------------------------------------------+
| <Home>         | <Create> <Delete> <Clone> <Boot v> <Transfer> <Shell>     <Edit> |
| >Sandboxes<    |------------------------------------------------------------------|
| <Applications> |                 | No sandboxes available. Click "Create" to make |
| <Logs>         |                 | your first sandbox.                            |
|                |                 |                                                |
| <Running Jobs> |                 |                                                |
| {------------} |                 |                                                |
+-----------------------------------------------------------------------------------+
```

If sandboxes exist:

```
* All buttons in the top bar are clickable, except for "Transfer" and "Shell"
  which are grayed out.
* Radio buttons in the sandbox list are clickable.
* All UI elements in the configuration pane (furthest to the right) are grayed
  out.
* The configuration pane will be in a scrollable area, but it is shown fully
  expanded here.

+-----------------------------------------------------------------------------------+
| @ Sandbox Manager                                                           v ^ X |
+-----------------------------------------------------------------------------------+
| <Home>         | <Create> <Delete> <Clone> <Boot v> <Transfer> <Shell>     <Edit> |
| >Sandboxes<    |------------------------------------------------------------------|
| <Applications> | >o< Element     | Info                                           |
| <Logs>         |     Off         |                                                |
|                |-----------------|          Name: _Element_                       |
|                | <o> Tor-Browser |   Description:                                 |
|                |     Off         |   +------------------------------------------+ |
|                |-----------------|   | Use this for public rooms + private chat | |
|                | <o> Web Dev     |   | with Mallory                             | |
|                |     On (update) |   |                                          | |
|                |-----------------|   | Do NOT use this to communicate with Alice| |
|                |                 |   +------------------------------------------+ |
|                |                 |                                                |
|                |                 |------------------------------------------------|
|                |                 | Resources                                      |
|                |                 |                                                |
|                |                 |   Root volume: <20 GiB ^v>                     |
|                |                 |   Data volume: <10 GiB ^v>                     |
|                |                 |        Memory: < 2 GiB ^v>                     |
|                |                 |    CPU weight: <    50 ^v>                     |
|                |                 |    I/O weight: <    50 ^v>                     |
|                |                 |                                                |
|                |                 |------------------------------------------------|
|                |                 | Permissions                                    |
|                |                 |                                                |
|                |                 |   [ ] Play and record audio                    |
|                |                 |   [x] Access the system's GUI (Wayland)        |
|                |                 |   [ ] Access the system's GUI (X11)            |
|                |                 |   [ ] Accelerate graphics                      |
|                |                 |   [x] Access the network / Internet            |
|                |                 |   [x] Allow nested sandboxing                  |
|                |                 |                                                |
|                |                 |------------------------------------------------|
|                |                 | Sharing                                        |
|                |                 |                                                |
|                |                 |   Files and Folders:                           |
|                |                 |   +------------------------------------------+ |
|                |                 |   | RW | .../sandbox-shared | .../shared     | |
|                |                 |   | RO | .../user/Documents | .../Documents  | |
|                |                 |   +------------------------------------------+ |
|                |                 |                                        <+> <-> |
|                |                 |                                                |
|                |                 |   Devices:                                     |
|                |                 |   +------------------------------------------+ |
|                |                 |   | /dev/video1                              | |
|                |                 |   +------------------------------------------+ |
| <Running Jobs> |                 |                                        <+> <-> |
| {------------} |                 |                                                |
+-----------------------------------------------------------------------------------+
```

* When "Create" is clicked, opens the Create Sandbox screen as a new window.
* When "Delete" is clicked, opens the Delete Sandbox screen as a new window.
* When "Clone" is clicked, opens the Clone Sandbox screen as a new window.
* When "Boot" is clicked, switches to the Sandboxes screen (boot combo box).
* When "Edit" is clicked, switches to the Sandboxes screen (edit mode).
* When one of the radio buttons for sandboxes is clicked, switches between
  variants of the Sandboxes screen as appropriate.
* Note that we may spontaneously transition between this screen and other
  state-related screens.
  * Similarly, any sandbox in the sandbox list may have its state
    spontaneously change to any valid value.
  * Similarly, error messages may appear if the backend sends a message
    indicating that something failed.
  * Similarly, new sandboxes may appear or existing sandboxes may vanish at
    any time.

## Sandboxes screen (boot combo box)

```
+-----------------------------------------------------------------------------------+
| @ Sandbox Manager                                                           v ^ X |
+-----------------------------------------------------------------------------------+
| <Home>         | <Create> <Delete> <Clone> <Boot v> <Transfer> <Shell>     <Edit> |
| >Sandboxes<    |---------------------------+--------------------------------------------------------+
| <Applications> | >o< Element     | Info    | Boot in work mode (non-persistent except for data dir) |
| <Logs>         |     Off         |         | Boot in update mode (persistent, data dir unavailable) |
|                |-----------------|         +--------------------------------------------------------+
|                | <o> Tor-Browser |   Description:                               | |
|                |     Off         |   +----------------------------------------+ |^|
|                |-----------------|   | Use this for public rooms + private    | |||
|                | <o> Web Dev     |   | chat with Mallory                      | |v|
|                |     On (update) |   |                                        | | |
| <Running Jobs> |-----------------|   | Do NOT use this to communicate with    | | |
| {------------} |                 |   | Alice                                  | | |
+-----------------------------------------------------------------------------------+
```

* When the combo box closes, returns to Sandboxes screen (normal mode).
* If either button in the combo box is clicked, tells the backend to boot a
  sandbox in the appropriate mode and freezes the UI.
  * If the sandbox exists and is powered off, the backend sends back info
    that adds a Boot Sandbox job. Once that happens, the UI unfreezes.
  * If the sandbox does not exist, the backend informs the frontend of this. A
    Sandbox Not Found screen opens in a new window.
  * If the sandbox is powered on, the backend informs the frontend of this. A
    Sandbox Already Running screen opens in a new window.
* If the selected sandbox's state changes due to external factors, closes the
  combo box.

## Sandboxes screen (booting mode)

```
* All buttons in the top bar are clickable, except for "Delete", "Clone", and
  "Edit" which are grayed out.

+------------------------------------------------------------------------------------+
| @ Sandbox Manager                                                            v ^ X |
+------------------------------------------------------------------------------------+
| <Home>         | <Create> <Delete> <Clone> <Power v> <Transfer> <Shell>     <Edit> |
| >Sandboxes<    |-------------------------------------------------------------------|
| <Applications> | >o< Element      | Info                                         | |
| <Logs>         |     On (work,    |                                              | |
|                |     booting)     |          Name: _Element_                     | |
|                |------------------|   Description:                               | |
|                | <o> Tor-Browser  |   +----------------------------------------+ |^|
|                |     Off          |   | Use this for public rooms + private    | |||
|                |------------------|   | chat with Mallory                      | |v|
|                | <o> Web Dev      |   |                                        | | |
|                |     On (update)  |   | Do NOT use this to communicate with    | | |
| <Running Jobs> |------------------|   | Alice                                  | | |
| {------------} |                  |   |                                        | | |
+------------------------------------------------------------------------------------+
```

* When "Create" is clicked, opens the Create Sandbox screen as a new window.
* When "Power" is clicked, switches to the Sandboxes screen (power combo box).
* When "Transfer" is clicked, opens the Transfer Data screen as a new window
* When "Shell" is clicked, spawns a terminal window attached to the sandbox
  console. (This is purely CLI-based and the GUI will depend on the user's
  default terminal, so this is not elaborated on here.)
* When one of the radio buttons for sandboxes is clicked, switches between
  variants of the Sandboxes screen as appropriate.

## Sandboxes screen (booted mode)

Identical to "booting mode", except for "(work, booting)" or "(update,
booting)" on the selected sandbox will be "(work)" or "(update)" instead.

## Sandboxes screen (power combo box)

```
+------------------------------------------------------------------------------------+
| @ Sandbox Manager                                                            v ^ X |
+------------------------------------------------------------------------------------+
| <Home>         | <Create> <Delete> <Clone> <Power v> <Transfer> <Shell>     <Edit> |
| >Sandboxes<    |---------------------------+------------------+--------------------|
| <Applications> | >o< Element      | Info   | Shutdown cleanly |                  | |
| <Logs>         |     On (work)    |        | Force shutdown   |                  | |
|                |------------------|        +------------------+                  | |
|                | <o> Tor-Browser  |   Description:                               | |
|                |     Off          |   +----------------------------------------+ |^|
|                |------------------|   | Use this for public rooms + private    | |||
|                | <o> Web Dev      |   | chat with Mallory                      | |v|
|                |     On (update)  |   |                                        | | |
| <Running Jobs> |------------------|   | Do NOT use this to communicate with    | | |
| {------------} |                  |   | Alice                                  | | |
+------------------------------------------------------------------------------------+
```

* When the combo box closes, returns to Sandboxes screen (booting mode) or
  Sandboxes screen (booted mode).
* If either button in the combo box is clicked, tells the backend to shut down
  a sandbox in the appropriate mode and freezes the UI.
  * If the sandbox exists and is powered on, the backend sends back info that
    adds a Shutdown Sandbox job. Once that happens, the UI unfreezes.
  * If the sandbox does not exist, the backend informs the frontend of this. A
    Sandbox Not Found screen opens in a new window.
  * If the sandbox is powered off, the backend informs the frontend of this. A
    Sandbox Not Running screen opens in a new window.
* If the selected sandbox changes state due to external factors, closes the
  combo box.

## Sandboxes screen (shutting down mode)

Identical to "booting mode", except for "(booting)" on the selected sandbox
will be "(shutting down)" instead.

## Sandboxes screen (edit mode)

```
* All buttons in the sidebar, the sandbox list, and the top bar are grayed
  out, except for "Apply".
* All UI elements in the configuration pane become accessible.

+-------------------------------------------------------------------------------------------+
| @ Sandbox Manager                                                                   v ^ X |
+-------------------------------------------------------------------------------------------+
| <Home>         | <Create> <Delete> <Clone> <Boot v> <Transfer> <Shell>   <Apply> <Cancel> |
| >Sandboxes<    |--------------------------------------------------------------------------|
| <Applications> | >o< Element     | Info                                                   |
| <Logs>         |     Off         |                                                        |
|                |-----------------|          Name: _Element_                               |
|                | <o> Tor-Browser |   Description:                                         |
|                |     Off         |   +--------------------------------------------------+ |
|                |-----------------|   | Use this for public rooms + private chat with    | |
|                | <o> Web Dev     |   | Mallory                                          | |
|                |     On (update) |   |                                                  | |
|                |-----------------|   | Do NOT use this to communicate with Alice        | |
|                |                 |   +--------------------------------------------------+ |
|                |                 |                                                        |
|                |                 |--------------------------------------------------------|
|                |                 | Resources                                              |
|                |                 |                                                        |
|                |                 |   Root volume: <20 GiB ^v>                             |
|                |                 |   Data volume: <10 GiB ^v>                             |
|                |                 |        Memory: < 2 GiB ^v>                             |
|                |                 |    CPU weight: <    50 ^v>                             |
|                |                 |    I/O weight: <    50 ^v>                             |
|                |                 |                                                        |
|                |                 |--------------------------------------------------------|
|                |                 | Permissions                                            |
|                |                 |                                                        |
|                |                 |   [ ] Play and record audio                            |
|                |                 |   [x] Access the system's GUI (Wayland)                |
|                |                 |   [ ] Access the system's GUI (X11)                    |
|                |                 |   [ ] Accelerate graphics                              |
|                |                 |   [x] Access the network / Internet                    |
|                |                 |   [x] Allow nested sandboxing                          |
|                |                 |                                                        |
|                |                 |--------------------------------------------------------|
|                |                 | Sharing                                                |
|                |                 |                                                        |
|                |                 |   Files and Folders:                                   |
|                |                 |   +--------------------------------------------------+ |
|                |                 |   | RW | /home/user/sandbox-shared | .../shared      | |
|                |                 |   | RO | /home/user/Documents      | .../Documents   | |
|                |                 |   +--------------------------------------------------+ |
|                |                 |                                                <+> <-> |
|                |                 |                                                        |
|                |                 |   Devices:                                             |
|                |                 |   +--------------------------------------------------+ |
|                |                 |   | /dev/video1                                      | |
|                |                 |   +--------------------------------------------------+ |
| <Running Jobs> |                 |                                                <+> <-> |
| {------------} |                 |                                                        |
+-------------------------------------------------------------------------------------------+
```

* Clicking the "+" button under Sharing -> Files and Folders opens the Add
  Shared Folder screen in a new window.
* Clicking the "-" button under Sharing -> Files and Folders removes an entry
  from the shared folders list.
* Clicking the "+" button under Sharing -> Devices opens the Add Shared Device
  screen in a new window.
+ Clicking the "-" button under Sharing -> Devices removes an entry from the
  shared device list.
* Other UI elements react as one would expect (editable text boxes, toggleable
  checkboxes).
* Clicking "Apply" tells the backend to reconfigure the sandbox, and freezes
  the UI.
  * If the new configuration uses a sandbox name that is either new and unique
    or the same as previously, the config passes validation, the sandbox isn't
    running, and the sandbox exists, the backend sends back info that adds a
    Config Sandbox job.
  * If the new sandbox name is identical to the name of a different existing
    sandbox, the backend informs the frontend of this. A Duplicate Sandbox
    Name screen opens in a new window.
  * If the configuration data fails validation for some reason, the backend
    informs the frontend of this. A Sandbox Configuration Bug screen is then
    opened in a new window.
  * If the sandbox is already running, the backend informs the frontend of
    this. A Sandbox Already Running screen opens in a new window.
  * If the sandbox no longer exists, the backend informs the frontend of this.
    A Sandbox Not Found screen opens in a new window.
* Clicking "Cancel" discards all config changes and returns to Sandboxes
  screen (normal mode).
* If the sandbox's state changes, kicks the user out of edit mode and switches
  to the appropriate variant of the Sandboxes screen.

## Sandboxes screen (config mode)

```
* All buttons in the top bar are grayed out except for "Create"

+------------------------------------------------------------------------------------+
| @ Sandbox Manager                                                            v ^ X |
+------------------------------------------------------------------------------------+
| <Home>         | <Create> <Delete> <Clone> <Boot v> <Transfer> <Shell>      <Edit> |
| >Sandboxes<    |-------------------------------------------------------------------|
| <Applications> | >o< Element      | Info                                         | |
| <Logs>         |     Off (config) |                                              | |
|                |------------------|          Name: _Element_                     | |
|                | <o> Tor-Browser  |   Description:                               | |
|                |     Off          |   +----------------------------------------+ |^|
|                |------------------|   | Use this for public rooms + private    | |||
|                | <o> Web Dev      |   | chat with Mallory                      | |v|
|                |     On (update)  |   |                                        | | |
| <Running Jobs> |------------------|   | Do NOT use this to communicate with    | | |
| {-=-=-=-=-=-=} |                  |   | Alice                                  | | |
+------------------------------------------------------------------------------------+
```

* When "Create" is clicked, opens the Create Sandbox screen as a new window.

## Sandboxes screen (create mode)

* UI is same as Sandboxes screen (config mode), except for it says "(create)"
  rather than "(config)".

## Sandboxes screen (delete mode)

* UI is same as Sandboxes screen (config mode), except for it says "(delete)"
  rather than "(config)".

## Sandboxes screen (clone mode)

* UI is the same as Sandboxes screen (config mode), except for it says
  "(clone)" rather than "(config)".

## Applications screen (running sandbox in work mode selected, unpinned app selected)

```
+-----------------------------------------------------------------------------------+
| @ Sandbox Manager                                                           v ^ X |
+-----------------------------------------------------------------------------------+
| <Home>         | <Info> <Pin> <Launch>                                            |
| <Sandboxes>    |------------------------------------------------------------------|
| >Applications< | >o< Element      | v Pinned apps                                 |
| <Logs>         |     On (work)    |   - Element                                   |
|                |------------------|   - Terminal                                  |
|                | <o> Tor-Browser  | v Internet                                    |
|                |     Off          |   - Element                                   |
|                |------------------|   - Firefox <---                              |
|                | <o> Web Dev      | > System                                      |
|                |     On (update)  |                                               |
|                |------------------|                                               |
| <Running Jobs> |                  |                                               |
| {------------} |                  |                                               |
+-----------------------------------------------------------------------------------+
```

* If information about apps in the sandbox cannot be gotten, the App List
  Fetch Failed screen opens in a new window, and only pinned apps are shown.
* Clicking "Info" opens the App Info screen in a new window. If app info
  cannot be gotten, the App Info Fetch Failed screen opens in a new window.
* Clicking "Pin" pins the app to the Start Menu and adds it to the pinned apps
  category. If this fails because app info could not be fetched, the App Info
  Fetch Failed screen opens in a new window. Otherwise, the Pin Failed screen
  opens in a new window.
* Clicking "Launch" launches the app in the sandbox and freezes the UI.
  * If the application launch succeeds, the backend informs the frontend of
    this, and the UI unfreezes.
  * If the application launch fails, the backend informs the frontend of this.
    The Application Launch Failed screen is opened in a new window, and the UI
    unfreezes.

## Applications screen (running sandbox in work mode selected, pinned app selected)

Same as above, but "Pin" changes to "Unpin". Clicking it unpins the app from
the Start Menu and removes it from the pinned apps category. If this fails,
the Unpin Failed screen opens in a new window.

## Applications screen (running sandbox in update mode selected)

Same as the above two screens, but the "Launch" button is grayed out.

## Applications screen (powered off sandbox selected)

Same as above, but the Launch button is grayed out, and only pinned apps are
displayed.

## Logs screen

```
+-----------------------------------------------------------------------------------+
| @ Sandbox Manager                                                           v ^ X |
+-----------------------------------------------------------------------------------+
| <Home>         | Frontend logs contain details about what the Sandbox Manager app |
| <Sandboxes>    | is doing.                                                        |
| >Applications< |                                                                  |
| <Logs>         |                                             <View Frontend Logs> |
|                |                                                                  |
|                |                                                                  |
|                | Backend logs contain details about what the sandbox-manager-dist |
|                | engine is doing.                                                 |
|                |                                                                  |
| <Running Jobs> |                                              <View Backend Logs> |
| {------------} |                                                                  |
+-----------------------------------------------------------------------------------+
```

* Clicking "View Frontend Logs" displays the frontend logs in a text editor.
  If this fails, a View Frontend Logs Failed screen is opened in a new window.
* Clicking "View Backend Logs" displays the backend logs in a text editor. If
  this fails, a View Backend Logs Failed screen is opened in a new window.

## Create Sandbox screen

```
* "Create" is grayed out if the "Name" matches the name of a known existing
  sandbox.

+------------------------------------------------+
| @ Create Sandbox - Sandbox Manager       v ^ X |
+------------------------------------------------+
| Info                                           |
|                                                |
|          Name: _Type name here_                |
|   Description:                                 |
|   +----------------------------------------+   |
|   | Type description here.                 |   |
|   |                                        |   |
|   | It can span multiple lines if desired. |   |
|   +----------------------------------------+   |
|                                                |
|------------------------------------------------|
| Resources                                      |
|                                                |
|   Root volume: <2 GiB ^v>                      |
|   Data volume: <1 GiB ^v>                      |
|        Memory: <1 GiB ^v>                      |
|    CPU weight: <   50 ^v>                      |
|    I/O weight: <   50 ^v>                      |
|                                                |
|------------------------------------------------|
| Permissions                                    |
|                                                |
|   [ ] Play and record audio                    |
|   [x] Access the system's GUI (Wayland)        |
|   [ ] Access the system's GUI (X11)            |
|   [ ] Accelerate graphics                      |
|   [x] Access the network / Internet            |
|   [x] Allow nested sandboxing                  |
|                                                |
|------------------------------------------------|
| Sharing                                        |
|                                                |
|   Files and Folders:                           |
|   +------------------------------------------+ |
|   | RW | .../sandbox-shared | .../shared     | |
|   | RO | .../user/Documents | .../Documents  | |
|   +------------------------------------------+ |
|                                        <+> <-> |
|                                                |
|   Devices:                                     |
|   +------------------------------------------+ |
|   | /dev/video1                              | |
|   +------------------------------------------+ |
|                                        <+> <-> |
|------------------------------------------------|
|                              <Create> <Cancel> |
+------------------------------------------------+
```

* Most UI elements react the same way as described in Sandboxes screen (edit
  mode).
* Clicking "Create" closes the window and tells the backend to create a new
  sandbox.
  * If the new sandbox name is unique and the config passes validation, the
    backend sends back info that adds a Create Sandbox job.
  * If the new sandbox name is identical to an existing name, the backend
    informs the frontend of this. A Duplicate Sandbox Name screen is then
    opened in a new window.
  * If the configuration data fails validation for some reason, the backend
    informs the frontend of this. A Sandbox Configuration Bug screen is then
    opened in a new window.
* Clicking "Cancel" closes the window.

## Delete Sandbox screen

```
* "OK" button is grayed out unless the correct sandbox name is present in the
  text field

+-------------------------------------------------------------+
| @ Delete Sandbox - Sandbox Manager                    v ^ X |
+-------------------------------------------------------------+
| Are you sure you want to remove the sandbox "New-Test"? All |
| data in the sandbox will be lost!                           |
|                                                             |
| Type the name of the sandbox ("New-Test") below to confirm: |
|                                                             |
| ___________________________________________________________ |
|                                                             |
|                                               <OK> <Cancel> |
+-------------------------------------------------------------+
```

* Clicking "OK" closes the window, tells the backend to delete a sandbox, and
  freezes the UI.
  * If the sandbox exists and is powered off, the backend sends back info that
    adds a Delete Sandbox job. Once that happens, the window closes.
  * If the sandbox does not exist, the backend informs the frontend of this. A
    Sandbox Not Found screen opens in a new window.
  * If the sandbox is powered on, the backend informs the frontend of this. A
    Sandbox Already Running screen opens in a new window.
* Clicking "Cancel" closes the window.

## Clone Sandbox screen

```
* "Clone" button is grayed out unless something has been typed into "Clone
  name"

+-------------------------------------------+
| @ Clone Sandbox - Sandbox Manager   v ^ X |
+-------------------------------------------+
| Source sandbox: Element                   |
|     Clone name: _________________________ |
|                                           |
|                          <Clone> <Cancel> |
+-------------------------------------------+
```

* Clicking "Clone" tells the backend to clone a sandbox and freezes the UI.
  * If the source sandbox exists, is powered off, and the name of the new
    sandbox is unique, the backend sends back info that adds a Clone Sandbox
    job. Once that happens, the window closes.
  * If the source sandbox does not exist, the backend informs the frontend of
    this. A Sandbox Not Found screen opens in a new window.
  * If the source sandbox is powered on, the backend informs the frontend of
    this. A Sandbox Already Running screen opens in a new window.
  * If the new sandbox name is not unique, the backend informs the frontend of
    this. A Duplicate Sandbox Name screen opens in a new window.
* If the source sandbox's state changes, the window abruptly closes and the UI
  switches to the appropriate variant of the Sandboxes screen.
* Clicking "Cancel" closes the window.

## Transfer Data screen

```
+-------------------------------------------+
| @ Transfer Data - Sandbox Manager   v ^ X |
+-------------------------------------------+
|                                           |
| +------------+                            |
| | To sandbox |---------+                  |
| |            | To host |                  |
| +---------------------------------------+ |
| | Source path: _______________ <Browse> | |
| | Target path: _______________ <Browse> | |
| +---------------------------------------+ |
|                                           |
|                       <Transfer> <Cancel> |
+-------------------------------------------+
```

* Clicking "Transfer" tells the backend to start a data transfer and freezes
  the UI.
  * If the source sandbox exists and is powered on, the source file or
    directory exists, and the target file or directory does not exist, the
    backend sends back info that adds a Transfer Data job. Once that happens,
    the window closes.
  * If the source sandbox does not exist, the backend informs the frontend of
    this. A Sandbox Not Found screen opens in a new window.
  * If the source sandbox is powered off, the backend informs the frontend of
    this. A Sandbox Not Running screen opens in a new window.
  * If the source file or directory does not exist, a File or Directory Missing
    screen opens in a new window. The backend will have informed the frontend
    of the issue if the source file is in the sandbox.
  * If the target file or directory exists, a File or Directory Exists screen
    opens in a new window. The backend will have informed the frontend of the
    issue if the target file is in the sandbox.
* If the sandbox's state changes, the window abruptly closes and the UI
  switches to the appropriate variant of the Sandboxes screen.
* Clicking "Cancel" closes the window.
* Clicking "Browse" opens a Browse Files screen in a new window.

## Browse Files screen

```
+------------------------------------------+
| @ Browse Files - Sandbox Manager   v ^ X |
+------------------------------------------+
|                                          |
| +--------------------------------------+ |
| | > /bin [root:root, 0755]           | | |
| | > /boot [root:root, 0700]          |^| |
| | > /dev [root:root, 0755]           ||| |
| | > /efi [ERROR, click "Refresh"]    |v| |
| | > /etc [root:root, 0755]           | | |
| | v /home [root:root, 0755]          | | |
| |   > sysmaint [sysmaint:sysmain...] | | |
| |   v user [user:user, 0700]         | | |
| |     > Documents [user:user, 0755]  | | |
| |     - donuts.docx [user:user, ...] | | |
| |     > Downloads [user:user, 0755]  | | |
| +--------------------------------------+ |
|                                          |
| <Refresh>              <Select> <Cancel> |
+------------------------------------------+
```

* Clicking "Refresh" rebuilds the directory tree, keeping nodes open that were
  open to begin with if they still exist.
* Clicking "Select" populates the path field from the previous screen with the
  path to the selected file or directory and closes the window.
* Clicking "Cancel" closes the window.
* Implementation note, this will use standard UNIX APIs to browse files and
  directories on the host, but will communicate with the backend to browse
  files and directories in the sandbox.
* We also should avoid popping an error message in the user's face here if at
  all possible. If we can't load something, display `ERROR, click "Refresh"`
  and log the issue.

## App Info screen

```
+-------------------------------------------+
| @ App Info - Sandbox Manager        v ^ X |
+-------------------------------------------+
|         Name: _Firefox___________________ |
| Generic Name: _Web Browser_______________ |
|      Comment: _Fast and private browser__ |
|         Exec: _firefox %u________________ |
|     Work Dir: ___________________________ |
|                                           |
| Supported file types:                     |
| +---------------------------------------+ |
| | video/webm    image/avif              | |
| | video/ogg     audio/webm              | |
| | text/html     audio/ogg               | |
| | image/webp    audio/flac              | |
| | image/svg+xml application/xml         | |
| | image/png     application/xhtml+xml   | |
| | image/jpeg    application/x-xpinstall | |
| | image/gif     application/rss+xml     | |
| +---------------------------------------+ |
|                                           |
|                                      <OK> |
+-------------------------------------------+
```

* Clicking "OK" closes the window.

## Running Jobs screen

```
+----------------------------------------------------+
| @ Running Jobs - Sandbox Manager             v ^ X |
+----------------------------------------------------+
|     Job type: Create Sandbox                       |
| Sandbox name: Element                              |
| Sandbox UUID: abcdef12-3456-7890-1234-abcdef123456 |
|     Progress: {-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=} |
|                                                    |
|                                           <Cancel> |
|----------------------------------------------------|
|     Job type: Delete Sandbox                       |
| Sandbox name: garbage                              |
| Sandbox UUID: abcdef12-3456-7890-1234-abcdef123457 |
|     Progress: {-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=} |
|----------------------------------------------------|
|     Job type: Transfer Data                        |
| Sandbox name: Element                              |
| Sandbox UUID: abcdef12-3456-7890-1234-abcdef123456 |
|    Direction: Host to Sandbox                      |
|  Source path: /home/user/Documents/stuff           |
|  Target path: /home/user/tmp                       |
|     Progress: {=========                         } |
|                                                    |
|                                           <Cancel> |
|----------------------------------------------------|
|                                               <OK> |
+----------------------------------------------------+
```

* Clicking "Cancel" on a job takes the action appropriate for that job. Not
  all jobs can be cancelled.
* Clicking "OK" closes the window.
* It is possible to open this screen even if no jobs are running.

## Jobs Still Running screen (no data transfer jobs)

```
+---------------------------------------------------------------------+
| @ Data Transfer Incomplete - Sandbox Manager                  v ^ X |
+---------------------------------------------------------------------+
| One or more data transfer jobs are running. Closing Sandbox Manager |
| will interrupt them. Are you sure you want to do this?              |
|                                                                     |
|                                                       <OK> <Cancel> |
+---------------------------------------------------------------------+
```

* Clicking "OK" interrupts data transfer jobs and closes Sandbox Manager.
* Clicking "Cancel" closes the window.

## Restart Backend screen

```
+--------------------------------------------------------------------+
| @ Restart Backend - Sandbox Manager                          v ^ X |
+--------------------------------------------------------------------+
| The sandbox manager backend has been updated, and must restart for |
| updates to apply. Would you like to restart it now?                |
|                                                                    |
| WARNING: There are running sandboxes present. Restarting the       |
| backend will forcibly close all applications running inside them   |
| and will shut the sandboxes down.                                  |
|                                                                    |
| WARNING: There are running jobs present. Restarting the backend    |
| will cancel all cancellable running jobs.                          |
|                                                                    |
|                                                   <Restart> <Skip> |
+--------------------------------------------------------------------+
```

* The running sandboxes warning is not displayed if there are no running
  sandboxes.
* The running jobs warning is not displayed if there are no running jobs.
* Clicking "Restart" closes the window, freezes the UI, and tells the backend
  to restart itself.
  * If the backend accepts the request, the frontend disconnects from the
    backend and attempts to reconnect.
    * If reconnection succeeds, the UI unfreezes.
    * If reconnection fails, a Connection Lost screen opens in a new window.
  * If the backend refuses the request, the UI unfreezes and a Restart Denied
    screen opens in a new window.
* Clicking "Skip" closes the window.

## Damaged Sandboxes screen

```
+--------------------------------------------------------------------------------+
| @ Damaged Sandboxes - Sandbox Manager                                    v ^ X |
+--------------------------------------------------------------------------------+
| The following sandboxes belonging to this user are damaged and cannot be used: |
|                                                                                |
| * Element                                                                      |
|   * Path: /home/sandbox-manager-dist/1000/abcdef12-3456-7890-1234-abcdef123456 |
| * <unknown>                                                                    |
|   * Path: /home/sandbox-manager-dist/1000/abcdef12-3456-7890-1234-abcdef123457 |
|                                                                                |
| If you did not change these sandboxes manually, they were most likely left     |
| behind by an interrupted create or delete process. In these situations, it is  |
| generally safe to simply delete the corrupted files.                           |
|                                                                                |
| Would you like to delete the damaged sandboxes now?                            |
|                                                                                |
|                                                                <Delete> <Keep> |
+--------------------------------------------------------------------------------+
```

* Clicking "Delete" closes this window, freezes the UI, and tells the backend
  to delete the damaged sandboxes.
  * If deleting the damaged sandboxes succeeds, the backend sends back info
    indicating this. Once that happens, the Damaged Sandboxes Deleted screen
    opens in a new window.
  * If deleting the damaged sandboxes fails, the backend sends back info
    indicating this. Once that happens, the Damaged Sandbox Deletion Failed
    screen opens in a new window.
* Clicking "Keep" closes this window and opens the Skipping Damaged Sandbox
  Deletion screen in a new window.

## Damaged Sandboxes Deleted screen

```
+-----------------------------------------------------------------+
| @ Damaged Sandboxes Deleted - Sandbox Manager             v ^ X |
+-----------------------------------------------------------------+
| All damaged sandboxes belonging to this user have been deleted. |
|                                                                 |
|                                                            <OK> |
+-----------------------------------------------------------------+
```

## Skipping Damaged Sandbox Deletion screen

```
+------------------------------------------------------------------+
| @ Skipping Damaged Sandbox Deletion - Sandbox Manager      v ^ X |
+------------------------------------------------------------------+
| Damaged sandboxes have not been deleted. They will not appear in |
| the user interface, but they are still present on disk. This     |
| notice will appear again the next time you open Sandbox Manager. |
|                                                                  |
|                                                             <OK> |
+------------------------------------------------------------------+
```

* Clicking "OK" closes the window.

## Restart Denied screen

```
+---------------------------------------------------------------------+
| @ Restart Denied - Sandbox Manager                            v ^ X |
+---------------------------------------------------------------------+
| The sandbox manager backend refused to restart! This may be because |
| other users on the system are actively running sandboxes.           |
|                                                                     |
|                                                                <OK> |
+---------------------------------------------------------------------+
```

* Clicking "OK" closes the window.

## Damaged Sandbox Deletion Failed screen

```
+------------------------------------------------------------------+
| @ Damaged Sandbox Deletion Failed - Sandbox Manager        v ^ X |
+------------------------------------------------------------------+
| The damaged sandboxes could not be deleted! The backend returned |
| the following error:                                             |
|                                                                  |
| PATH: Input/output error                                         |
|                                                                  |
|                                                             <OK> |
+------------------------------------------------------------------+
```

* Clicking "OK" closes the window.

## Sandbox Already Running screen

```
+----------------------------------------------------------------------+
| @ Sandbox Already Running - Sandbox Manager                    v ^ X |
+----------------------------------------------------------------------+
| The sandbox "Element" is already running! This can happen if another |
| program started it while you were working with the Sandbox Manager.  |
| See the backend logs for more information.                           |
|                                                                      |
|                                                                 <OK> |
+----------------------------------------------------------------------+
```

* Clicking "OK" closes the window.

## Sandbox Not Running screen

```
+-----------------------------------------------------------------------+
| @ Sandbox Not Running - Sandbox Manager                         v ^ X |
+-----------------------------------------------------------------------+
| The sandbox "Element" is not running! This can happen if another      |
| program shut it down while you were working with the Sandbox Manager. |
| See the backend logs for more information.                            |
|                                                                       |
|                                                                  <OK> |
+-----------------------------------------------------------------------+
```

* Clicking "OK" closes the window.

## Sandbox Not Found screen

```
+----------------------------------------------------------------------+
| @ Sandbox Not Found - Sandbox Manager                          v ^ X |
+----------------------------------------------------------------------+
| The sandbox "Element" could not be found! This can happen if another |
| program deleted it while you were working with the Sandbox Manager.  |
| See the backend logs for more information.                           |
|                                                                      |
|                                                                 <OK> |
+----------------------------------------------------------------------+
```

* Clicking "OK" closes the window.

## Duplicate Sandbox Name screen

```
+-------------------------------------------------------+
| @ Duplicate Sandbox Name - Sandbox Manager      v ^ X |
+-------------------------------------------------------+
| A sandbox named "Element" already exists! Delete that |
| sandbox first, or choose a different name.            |
|                                                       |
|                                                  <OK> |
+-------------------------------------------------------+
```

* Clicking "OK" closes the window.

## File or Directory Missing screen

```
+-----------------------------------------------------------+
| @ File or Directory Missing - Sandbox Manager       v ^ X |
+-----------------------------------------------------------+
| The source file or directory "/home/user/recipe.txt" does |
| not exist in the "Element" sandbox. Double-check the file |
| path and try again.                                       |
|                                                           |
|                                                      <OK> |
+-----------------------------------------------------------+
```

* Clicking "OK" closes the window.
* May refer to the host rather than the sandbox.

## File or Directory Exists screen

```
+---------------------------------------------------------------+
| @ File or Directory Exists - Sandbox Manager            v ^ X |
+---------------------------------------------------------------+
| The target file or directory "/home/user/recipe.txt" already  |
| exists on the host. Double-check the file path and try again. |
|                                                               |
|                                                          <OK> |
+---------------------------------------------------------------+
```

* Clicking "OK" closes the window.
* May refer to the sandbox rather than the host.

## Boot Failed screen

```
+-----------------------------------------------------------+
| @ Boot Failed - Sandbox Manager                     v ^ X |
+-----------------------------------------------------------+
| Booting the sandbox "Element" has failed! See the backend |
| logs for more information.                                |
|                                                           |
|                                                      <OK> |
+-----------------------------------------------------------+
```

* Clicking "OK" closes the window.

## Shutdown Failed screen

```
+-----------------------------------------------------------------+
| @ Shutdown Failed - Sandbox Manager                       v ^ X |
+-----------------------------------------------------------------+
| Shutting down the sandbox "Element" has failed! See the backend |
| logs for more information.                                      |
|                                                                 |
|                                                            <OK> |
+-----------------------------------------------------------------+
```

* Clicking "OK" closes the window.

## Configuration Failed screen

```
+-----------------------------------------------------------------+
| @ Configuration Failed - Sandbox Manager                  v ^ X |
+-----------------------------------------------------------------+
| Reconfiguring the sandbox "Element" has failed! See the backend |
| logs for more information.                                      |
|                                                                 |
|                                                            <OK> |
+-----------------------------------------------------------------+
```

* Clicking "OK" closes the window.

## Sandbox Creation Failed screen

```
+------------------------------------------------------------+
| @ Sandbox Creation Failed - Sandbox Manager          v ^ X |
+------------------------------------------------------------+
| Creating the sandbox "Element" has failed! See the backend |
| logs for more information.                                 |
|                                                            |
|                                                       <OK> |
+------------------------------------------------------------+
```

* Clicking "OK" closes the window.

## Sandbox Deletion Failed screen

```
+------------------------------------------------------------+
| @ Sandbox Deletion Failed - Sandbox Manager          v ^ X |
+------------------------------------------------------------+
| Deleting the sandbox "Element" has failed! See the backend |
| logs for more information.                                 |
|                                                            |
|                                                       <OK> |
+------------------------------------------------------------+
```

* Clicking "OK" closes the window.

## Sandbox Clone Failed screen

```
+------------------------------------------------------------+
| @ Sandbox Clone Failed - Sandbox Manager             v ^ X |
+------------------------------------------------------------+
| Cloning the sandbox "Element" to "New-Element" has failed! |
| See the backend logs for more information.                 |
|                                                            |
|                                                       <OK> |
+------------------------------------------------------------+
```

* Clicking "OK" closes the window.

## Data Transfer Failed screen

```
+---------------------------------------------------------+
| @ Data Transfer Failed - Sandbox Manager          v ^ X |
+---------------------------------------------------------+
| Copying PATH from the host to PATH in sandbox "Element" |
| failed! The following error occurred on the host side:  |
|                                                         |
| PATH: Input/output error                                |
|                                                         |
| See the frontend logs for more information.             |
|                                                         |
|                                                    <OK> |
+---------------------------------------------------------+
```

* Clicking "OK" closes the window.

## App List Fetch Failed screen

```
+------------------------------------------------------+
| @ App List Fetch Failed - Sandbox Manager      v ^ X |
+------------------------------------------------------+
| Could not get the list of apps in sandbox "Element"! |
| See the backend logs for more information.           |
|                                                      |
|                                                 <OK> |
+------------------------------------------------------+
```

* Clicking "OK" closes the window.

## App Info Fetch Failed screen

```
+---------------------------------------------------------------------+
| @ App Info Fetch Failed - Sandbox Manager                     v ^ X |
+---------------------------------------------------------------------+
| Could not get information for app "Firefox" from sandbox "Element"! |
| See the backend logs for more information.                          |
|                                                                     |
|                                                                <OK> |
+---------------------------------------------------------------------+
```

* Clicking "OK" closes the window.

## Pin Failed screen

```
+-----------------------------------------------------------------------+
| @ Pin Failed - Sandbox Manager                                  v ^ X |
+-----------------------------------------------------------------------+
| Could not pin app "Firefox" from sandbox "Element" to the start menu! |
| See the frontend logs for more information.                           |
|                                                                       |
|                                                                  <OK> |
+-----------------------------------------------------------------------+
```

* Clicking "OK" closes the window.

## Application Launch Failed screen

```
+-------------------------------------------------------------+
| @ Application Launch Failed - Sandbox Manager         v ^ X |
+-------------------------------------------------------------+
| Could not launch the "Firefox" application in the "Element" |
| sandbox! See the backends logs for more information.        |
|                                                             |
|                                                        <OK> |
+-------------------------------------------------------------+
```

* Clicking "OK" closes the window.

## View Frontend Logs Failed screen

```
+---------------------------------------------------------------+
| @ View Frontend Logs Failed - Sandbox Manager           v ^ X |
+---------------------------------------------------------------+
| Could not view frontend logs! Try viewing                     |
| ~/.local/share/sandbox-manager-dist/log.txt in a text editor. |
|                                                               |
|                                                          <OK> |
+---------------------------------------------------------------+
```

* Clicking "OK" closes the window.

## View Backend Logs Failed screen

```
+-----------------------------------------------------------+
| @ View Backend Logs Failed - Sandbox Manager        v ^ X |
+-----------------------------------------------------------+
| Could not view backend logs! Try running "sudo journalctl |
| -u sandbox-manager-dist.service" to view the logs.        |
|                                                           |
|                                                      <OK> |
+-----------------------------------------------------------+
```

* Clicking "OK" closes the window.
* If user-sysmaint-split is detected, this may tell the user to boot into
  sysmaint mode.

## Sandbox Configuration Bug screen

```
+------------------------------------------------------------------+
| @ Sandbox Configuration Bug - Sandbox Manager              v ^ X |
+------------------------------------------------------------------+
| The backend rejected the configuration options for the "Element" |
| sandbox! See the backend logs for more information.              |
|                                                                  |
| Please report this bug!                                          |
|                                                                  |
|                                                             <OK> |
+------------------------------------------------------------------+
```

* Clicking "OK" closes the window.

## Connection Lost screen

```
+-------------------------------------------------------------------+
| @ Connection Lost - Sandbox Manager                         v ^ X |
+-------------------------------------------------------------------+
| The connection to the backend was lost! This is possibly due to a |
| bug. Restart Sandbox Manager and view the frontend and backend    |
| logs for more information.                                        |
|                                                                   |
|                                                              <OK> |
+-------------------------------------------------------------------+
```

* Clicking "OK" closes Sandbox Manager.

## Backend Bug screen

```
+-----------------------------------------------------------------+
| @ Backend Bug - Sandbox Manager                           v ^ X |
+-----------------------------------------------------------------+
| The backend sent us an invalid message! Please report this bug! |
| Restart Sandbox Manager and view the frontend and backend logs  |
| for more information.                                           |
|                                                                 |
|                                                            <OK> |
+-----------------------------------------------------------------+
```

* Clicking "OK" closes Sandbox Manager.

# Job behavior

## Boot Sandbox job

* When job is added, the relevant sandbox's status changes to "On (work,
  booting)" or "On (update, booting)".
* If successful, the sandbox's status changes to "On (work)" or "On (update)".
* If this fails, the sandbox's status changes to "Off" and a Boot Failed
  screen is opened in a new window.
* If job is canceled, the sandbox's status changes to "Off".

## Shutdown Sandbox job

* When job is added, the relevant sandbox's status changes to "On (work,
  shutting down)" or "On (update, shutting down)".
* If successful, the sandbox's status changes to "Off".
* If this fails, the sandbox's status changes to "On (work)" or "On (update)",
  and a Shutdown Failed screen is opened in a new window.
* Job cannot be cancelled.

## Config Sandbox job

* When job is added, the relevant sandbox's status changes to "Off (config)".
* Whether successful or not, the sandbox's status changes to "Off" when the
  job finishes.
* If successful, the new configuration remains in place.
* If this fails, the original configuration is loaded back into the UI, and a
  Configuration Failed screen is opened in a new window.
* If job is cancelled, the original configuration is loaded back into the UI.

## Create Sandbox job

* When job is added, a new sandbox is added to the UI with the status "Off
  (create)".
* If successful, the sandbox's status changes to "Off".
* If this fails, the sandbox is removed from the UI, and a Sandbox Creation
  Failed screen is opened in a new window.
* If job is cancelled, the sandbox is removed from the UI.

## Delete Sandbox job

* When job is added, the relevant sandbox's status changes to "Off (delete)".
* If successful, the sandbox is removed from the UI.
* If this fails, the sandbox's state changes to "Off" and a Sandbox Deletion
  Failed screen is opened in a new window.

## Clone Sandbox job

* When job is added, a new sandbox is added to the UI with the status "Off
  (clone)".
* If successful, the sandbox's status changes to "Off".
* If this fails, the sandbox is removed from the UI, and a Sandbox Clone
  Failed screen is opened in a new window.
* If job is cancelled, the sandbox is removed from the UI.

## Transfer Data job

* When job is added, data transfer between the client and server begins.
* If successful, the job disappears.
* If this fails because the sandbox was powered off, a Sandbox Not Running
  screen opens in a new window.
* If this fails for some other reason, a Data Transfer Failed screen is opened
  in a new window.
* If job is cancelled, data transfer stops at whatever stage it's at.

# Start menu integration

* Use a dedicated section in the start menu for this
* Only apps the user has specifically configured to show up here should show
  up here
* Each app must be shown as its name and the sandbox it will be booted in
* Apps can only be started if the sandbox is booted in live mode (let's not
  allow adding persistent shortcuts at least to begin with)

# CLI design

Synopsis:

`sandbox-manager-cli MODE [ARGS...]`

Modes:

* `list` - List all available sandboxes.
* `create <sandbox-name> <config-options>` - Creates a new sandbox with the
  given name.
* `get-config <sandbox-UUID>` - Prints the configuration of the specified
  sandbox.
* `configure <sandbox-UUID> <config-options>` - Modifies the specified config
  options of the specified sandbox.
* `delete <sandbox-UUID>` - Deletes the specified sandbox.
* `clone <sandbox-UUID> <new-sandbox-name>` - Clones the specified sandbox.
* `boot <sandbox-UUID> <work|update>` - Boots the specified sandbox in the
  specified mode.
* `shutdown <sandbox-UUID> <normal|force>` - Shuts down the specified sandbox,
  either cleanly, or forcibly.
* `copy-to-host <sandbox-UUID> </path/in/sandbox> </path/in/host>` - Copies
  the specified file or directory from the sandbox to the host.
* `copy-to-sandbox <sandbox-UUID> </path/in/host> </path/in/sandbox>` - Copies
  the specified file or directory from the host to the sandbox.
* `shell <sandbox-UUID>` - Opens the specified sandbox's shell.
* `ls <sandbox-UUID> </path/in/sandbox>` - Lists the files and directories in
  the specified directory in the sandbox.
* `list-apps <sandbox-UUID>` - Lists the applications in the specified
  sandbox. Includes pinned apps.
* `get-app-info <sandbox-UUID> <desktop-file-name>` - Gets application info
  for the specified app. (This basically dumps the contents of the app's
  desktop file to stdout.)
* `pin-app <sandbox-UUID> <desktop-file-name>` - Pins the specified app to the
  start menu.
* `unpin-app <sandbox-UUID> <desktop-file-name>` - Unpins the specified app
  from the start menu.
* `launch-app <sandbox-UUID> <executable-path> [args...]` - Launches the
  specified executable in the sandbox.
* `dump-backend-logs` - Requests logs from the backend and dumps them to
  stdout.

All operations are synchronous. Exits 0 on success, non-zero on error. The
"shell" command is particularly important, as the GUI frontend actually uses
it for its "Shell" button rather than interacting with the backend's shell
interface directly.

# Backend design concerns:

* The backend may need to run as root without confinement or sandboxing.
  * Running as root is necessary to use systemd-nspawn, no confinement or
    sandboxing is necessary to allow features such as device and folder
    passthrough.
  * Alternatively, we could abandon systemd-nspawn and attempt to use a
    different containerization system instead.
    * bwrap does not appear to be suitable for this:
      https://github.com/containers/bubblewrap/issues/668
    * Something needs to run as root for this to work.
      * Either the container manager itself runs as root (systemd-nspawn),
      * or the container manager only maps a single UID into the container
        (this is what Flatpak does AFAIK),
      * or the container manager calls a SUID-root executable to handle UID
        mapping (this is what Podman does AFAIK).
  * If we were creating our own container backend from scratch, we could
    potentially write a privleap-like newuidmap alternative that would rely on
    UNIX sockets, and use that to implement unprivileged containers. This is
    probably going to be a lot of work.
  * Or, we could simply write a newuidmap/newgidmap alternative that relies on
    UNIX sockets, and functions as a drop-in replacement for the existing
    tools. Then we can use Podman as-is without problems. Then our run-as-root
    daemon becomes very small and likely attack-proof.
  * Unprivileged containers may be a bad idea in general. See
    https://www.redhat.com/en/blog/files-devices-podman (file and device
    sharing can be outright broken, solving this apparently requires reducing
    isolation between the container and host and still results in the
    container thinking the object's owning group is "nobody").  One also
    cannot use idmapped mounts, see
    https://github.com/containers/podman/issues/17753)
  * For now, accepting the risk of running as root, since this appears to be
    necessary to set up proper isolation while also allowing decent
    integration.
* What storage format should we use for the containers themselves? We can use
  either directories full of files, or disk images.
  * Pros of directories:
    * Easy to inspect from outside the container
    * Processes that have root access outside the container can freely modify
      the container in-place
    * Probably higher performance
  * Cons of directories:
    * Dirs containing mini operating systems contain lots of little files.
      This could potentially result in inode exhaustion if a user has a lot of
      sandboxes.
    * Hard to implement storage quotas
    * Files with SUID bits or capabilities can be dropped on the disk where
      the host can see them (note that I have not yet been able to actually
      make an executable that can get permissions via capability bits without
      SUID so it's unclear how much of a concern this is)
    * Possibly confusing to users; user sees a dir with the name of their
      sandbox on it, goes "oh, what's this?", opens it up, and sees what looks
      like an OS inside
  * Pros of disk images:
    * Fixed-size, quotas are easy
    * Opaque, therefore less confusing to end-users ("the disk image is the
      container")
    * Uses less inodes
    * Isolates the guest filesystem from the host to some degree (though not
      entirely because the filesystem is mounted where the host can see it
      *somewhere*, that's how the containerization program can work at all)
  * Cons of disk images:
    * Difficult to inspect without root permissions if the sandbox breaks
    * Lower performance due to having a filesystem within a filesystem
    * Higher attack surface during mount (if malware can modify the disk image
      directly, it can try to compromise the host kernel)
  * Unsure which one is the lesser risk at the moment. The ability to limit
    disk usage may be very important for users using filesystems such as
    BTRFS, which can lock up permanently if space is exhausted. Avoiding
    executables with capabilities or permission bits on the disk may also be a
    good idea. On the other hand, the kernel attack surface provided by using
    disk images here is very, very high, and would mandate making the disk
    images only readable and writable by root to prevent this from becoming a
    fatal vulnerability.
  * As described below, we're going to be storing the sandboxes in a directory
    where users cannot access them directly, so let's go with image files for
    now. Attackers won't be able to write to the image files unless they have
    root access to begin with.
  * Other options may exist, such as LVM, but this would require changing our
    partition layout, which is highly undesirable as it prevents easy rollout
    of this feature to existing users.
* Where should the containers be stored? Inside user home directories? Inside
  /home but not in individual home directories? Under /var? Somewhere else
  entirely?
  * Storing the containers somewhere under /home is preferable to fit in with
    our future plans for Verified Boot. /var in particular is unsuitable here
    since executable code (such as package postinst scripts) is stored under
    /var and so /var has to be validated by our Verified Boot implementation.
    We could exclude a directory under /var from validation, and then use that
    for container storage, but that is likely unnecessarily complicated.
  * Storing the containers inside individual user home directories would make
    the most sense from an organization standpoint, especially since different
    users will have different sandboxes. However, this also may allow users to
    delete or modify sandboxes without privileges and without going through
    the backend. It also means the backend has to mess with files in the
    user's home directory directly. Storing the containers in user home dirs
    is especially dangerous if we go the disk image route, because if malware
    can gain direct write access to the image at any point, it can try to
    compromise the kernel as described above.
    * The fact that the backend has to mess with files in user home
      directories is probably a dealbreaker. What if a user creates a sandbox,
      then swaps out its dir with a symlink to something it shouldn't be able
      to access, or something like that? This feels like a vulnerability risk.
  * Let's store the sandboxes in a dedicated directory under /home (maybe
    /home/sandbox-manager-dist). This works with Verified Boot, and avoids
    potential vulnerabilities.
* Should users have unrestricted root privileges inside the containers?
  * TL;DR: Yes. There's no point in preventing it, since users can gain root
    access within a user namespace without any form of privileges or backend
    anyway, so we don't remove any kernel attack surface by trying to restrict
    this. We'll just annoy users if we try to do something like require
    sysmaint mode to be used to install apps within sandboxes.
* Should not-logged-in users be able to use sandboxing?
  * End-users might want to run persistent services in a sandbox, such as a
    web server exposed to the Tor network. Our tool is explicitly designed to
    prevent escape, while containerization systems like Docker are not
    designed as much for this, so maybe it would be useful for this to work
    for that use case rather than users having to use Docker or similar.
    * This can be done without allowing all not-logged-in users to use
      sandboxing, since one can just make a systemd service or whatever that
      will create a comm socket for the user account that needs to be able to
      run something in a sandbox, before actually running the thing in a
      sandbox.
  * Except inasmuch as the sandbox backend provides attack surface, the
    sandbox backend doesn't provide privileges any higher than what a
    potentially untrusted user would have anyway (remember one can always get
    root in a user namespace on demand).
    * One kind of very-hard-to-avoid attack surface is disk quota
      circumvention. A user could abuse the sandboxing system to consume
      massive amounts of disk space without exceeding a disk quota.
  * Let's restrict what users can access the sandbox backend similar to how we
    restrict access to privleapd. It meaningfully reduces attack surface.
* Should we forcibly shut down all sandboxes for a user when the control
  socket is closed?
  * From an attack surface perspective, it probably makes sense to do this.
    Users don't expect some of their applications to continue running after
    they log out.
* Should we split parts of privleap out into Python libraries so we can share
  code between the various components?
  * The IPC protocol used by privleap is particularly attractive, as it embeds
    a lot of validation capabilities into the protocol itself.
    * sdwdate-gui would potentially benefit from the IPC protocol also,
      although perhaps less so.
  * Similarly, the SUID-less, user-restricted socket structure is attractive,
    since it allows keeping the backend's attack surface as small as possible
    (only users that need access get access).
  * We could split these bits of functionality into libraries,
    "python3-secure-ipc" for the IPC protocol, and "python3-suidless-kit" for
    the socket management stuff (since it would be a toolkit for developing
    applications that allow privilege elevation without SUID-root
    executables). Or we could put these libraries into helper-scripts, or just
    reimplement the code all over again.
  * Further design has shown that the architecture used in privleap will be
    unsuitable for this project, and that the protocol used by privleap has
    features that are superfluous and confusing for this use case. Skipping
    this for now.
* Should we allow copying directories into and out of the sandbox, not just
  files?
  * From a UX standpoint, yes, but we have to be careful from a security
    standpoint. The privileged backend is going to be doing the file copies,
    which means if we aren't careful, a malicious application may be able to
    gain access to files it shouldn't be able to access by copying them to and
    from a sandbox. If we only allow copying individual files, this isn't so
    much of an issue, because we can open the file first, then check
    permissions on it before copying its contents. But if we allow copying
    entire directories... I guess we can just do the file copy permissions
    check once for each file, so that if an attacker tries to do symlink
    tricks, we still only copy files the user is allowed to.
  * Another approach to make this safe would be to launch a helper process as
    the user that is making the file copy request, then do all I/O as that
    user. That way we offload all permission checking to the kernel, which is
    probably safer than reimplementing it ourselves. Or, shoot, we can even
    make the frontend provide the file contents itself, that would be even
    easier.
  * For now, let's provide a directory copy feature, but implement it under
    the hood as a directory creation message and a series of file copy
    messages, in which the frontend streams the file contents and relevant
    metadata to or from the sandbox.
* Should we allow the frontend to act as a full file manager for the sandbox,
  or should it only support the minimum functions for copying things into and
  out of the sandbox and rely on the user to already know things like where
  files are, what permissions they have, etc.?
  * It's probably safe to implement all of the protocol messages needed to
    make this into a fully-fledged file manager. It might also allow easier
    debugging, forensics, and recovery to be able to inspect a container even
    if one cannot run any applications in it or even get a working shell in
    it.
  * On the other hand, systemd's rescue and emergency modes should be
    available for this use case. We're going to need a sandbox-side agent to
    make these features work, so if systemd isn't even able to function, this
    feature won't function either.
  * This is likely to be the most complicated feature of the sandbox manager
    if we try to implement it.
  * Users will likely become confused if they don't have "Browse" buttons for
    finding files in the sandbox and on the host to copy between them. Let's
    implement this.
* Should we use tar to handle transfer of directories between the sandbox and
  the host?
  * tar has substantial attack surface (as it is written in C and has a lot of
    features), and is potentially easy to misuse in unsafe ways. Let's avoid
    this for now.

# Backend and protocol design

* The backend (hereafter referred to as "sandboxd") runs as root without
  confinement or sandboxing for the reasons described above.
* Similar to privleap, sandboxd creates a control socket that only root can
  connect to, and one communications socket for each logged-in user that is
  authorized to use sandboxd's features. Control clients will connect to the
  control socket to instruct the backend to create and delete comm sockets as
  necessary.
* Each sandbox consists of three components; two image files and a
  configuration file. One image contains the sandbox's root filesystem.
  Another image contains the sandbox's persistent data. The configuration file
  defines what permissions and resources the sandbox has access to.
* Sandboxes are stored under /home/sandbox-manager-dist. Each user has their
  own subdirectory here named after their UID (/home/sandbox-manager-dist/1000
  for instance). Each subdirectory has zero or more subdirectories, each one
  containing one sandbox.
* Each sandbox directory uses a UUID as the name. This avoids possible issues
  with renaming a directory that's actively in use or that is about to be
  used.
* Each sandbox directory then contains three files, "root.img", "data.img",
  and "config". These correspond to the root filesystem image, persistent data
  image, and configuration file, respectively.
* A simple message protocol is used for communication. Messages are
  length-prefixed binary blobs, consisting of a 16-bit unsigned big-endian
  message code, a 16-byte correlation ID, a NULL-terminated list of message
  arguments, and trailing binary data. The length prefix is a 32-bit unsigned
  big-endian integer. Each message has a name associated with it, which is not
  sent over the wire but is used internally and in log messages.
* Some of the comm messages in this protocol require that a series of related
  messages work together. Some of these messages may be sent in contexts that
  make it hard to tell how to interpret other messages in the absence of
  metadata. To mitigate this, all messages include an correlation ID. Messages
  that "go together" all use the same correlation ID, regardless of which
  direction those messages are being sent in.
  * For instance, when the frontend is streaming a file to the server, it will
    include a correlation ID with the `CREATE_FILE_BEGIN` command it sends to
    the backend. The `CREATE_FILE_BLOCK` and `CREATE_FILE_END` messages that
    come after that will all use the same correlation ID. All messages send
    from the server regarding this file transfer will similarly use the same
    correlation ID.
  * Both sides of the connection can introduce a new correlation ID. For
    instance, if one client reconfigures or deletes a sandbox while two
    clients are connected, the server will send messages about the new
    configuration or the deleted sandbox to the other client, with a
    correlation ID that client has never seen. Clients must handle this
    properly.
* The server makes a distinction between short-lived and long-lived clients.
  Short-lived clients only receive information they explicitly ask for, while
  long-lived clients receive all information about sandboxes belonging to the
  user the client runs as. Long-lived clients also receive live state updates.
* The server may leak correlation IDs between multiple clients. This ID has no
  value in attempting to attack other clients, as it contains no sensitive
  data and clients cannot break into each other's connections without using
  something like ptrace (which is restricted on Kicksecure and would allow
  interfering with connections even if correlation ID isolation was
  implemented). We may decide to stop reusing correlation IDs across multiple
  clients in the future if this proves to be unsafe.
  * TODO: Research if there is any way for this to go wrong. Previously, the
    design forbade this, but not forbidding it simplifies the server-side code
    quite a bit.
* The server **MUST NOT** leak state information between multiple users
  running on the same machine! For instance, if client 1 is running as account
  "user", and client 2 is running as account "bob", information about changes
  made to "bob"'s sandboxes must not be shared with "user".
  * There is one exception to this rule, `RESTART_INPROGRESS`. This message
    must be sent to all clients running under all users when it is sent, since
    all clients will be affected by a disconnect.
* Many of the features depend on a sandbox-side agent to act on behalf of the
  backend. This agent's source code and startup service are bind-mounted into
  the sandbox on boot, along with an agent UNIX socket that the backend listens
  on.
* The control protocol consists of the following messages:
  * Sent from client to server:
    * `REGISTER` - Asks the backend to create a comm socket for a user. Takes
      one argument, the name or UID of the user to create a socket for. Does
      not include a binary blob.
    * `UNREGISTER` - Asks the backend to destroy a comm socket for a user.
      Takes one argument, the name or UID of the user to destroy the socket
      of. Does not include a binary blob.
  * Send from server to client:
    * `REGISTER_SUCCESS` - Informs the frontend that the user socket has been
      created successfully. Takes no arguments. Does not include a binary
      blob.
    * `REGISTER_EXISTS` - Informs the frontend that the user socket already
      exists. Takes no arguments. Does not include a binary blob.
    * `REGISTER_FAILURE` - Informs the frontend that the user socket could not
      be created. Takes no arguments. Does not include a binary blob.
    * `UNREGISTER_SUCCESS` - Informs the frontend that the user socket has
      been destroyed. Takes no arguments. Does not include a binary blob.
    * `UNREGISTER_ABSENT` - Informs the frontend that the user socket does not
      exist. Takes no arguments. Does not include a binary blob.
    * `UNREGISTER_FAILURE` - Informs the frontend that the user socket could
      not be destroyed. Takes no arguments. Does not include a binary blob.
* The comm socket protocol consists of the following messages:
  * Sent from client to server:
    * `SYNC` - Informs the backend that the frontend is long-lived. Once sent,
      the client cannot go back to "short-lived mode". Introduces a new
      correlation ID. Takes no arguments. Does not include a binary blob.
      * Note - the correlation ID included with this message is garbage and
        will be (mostly) ignored.
    * `QUERY_NEED_RESTART` - Asks the backend if it needs to be restarted.
      Introduces a new correlation ID. Takes no arguments. Does not include a
      binary blob.
    * `RESTART` - Tells the backend to restart itself. Introduces a new
      correlation ID. Takes no arguments. Does not include a binary blob.
    * `CREATE_START` - Informs the backend that a series of messages are going
      to be sent that will define the configuration of a sandbox that should
      be newly created. Introduces a new correlation ID. Takes no arguments.
      Does not include a binary blob.
    * `CREATE_END` - Informs the backend that the messages defining the new
      sandbox to create have all been sent, and that the backend should create
      a sandbox with the specified parameters. Must be correlated to a
      `CREATE_START` message. Takes no arguments. Does not include a binary
      blob.
    * `CONFIG_START` - Informs the backend that a series of messages are going
      to be sent that will replace the configuration of an already existing
      sandbox. Introduces a new correlation ID. Takes one argument; the UUID
      of the sandbox to reconfigure. Does not include a binary blob.
    * `CONFIG_END` - Informs the backend that the messages replacing the
      configuration of an existing sandbox have all been sent, and that the
      backend should apply the new configuration. Must be correlated to a
      `CONFIG_START` message. Takes no arguments. Does not include a binary
      blob.
    * `GET_CONFIG` - Asks the backend to send the client the current
      configuration of the specified sandbox. Introduces a new correlation ID.
      Supports one argument; the UUID of the sandbox to read the configuration
      of.  Does not include a binary blob.
      * Note - there is no reason for a long-lived client to send this
        message.
    * `DELETE` - Tells the backend to delete a sandbox. Introduces a new
      correlation ID. Takes one argument; the UUID of the sandbox to delete.
      Does not include a binary blob.
    * `CLONE` - Tells the backend to clone a sandbox. Introduces a new
      correlation ID. Takes two arguments; the UUID of the sandbox to clone,
      and the name to give the new sandbox. Does not include a binary blob.
    * `BOOT` - Tells the backend to boot a sandbox. Introduces a new
      correlation ID. Takes two arguments; the UUID of the sandbox to start,
      and the mode to start it in (either "work" or "update"). Does not
      include a binary blob.
    * `SHUTDOWN` - Tells the backend to shut down a sandbox. Introduces a new
      correlation ID. Takes two arguments; the UUID of the sandbox to shut
      down, and either "shutdown" to do a clean shutdown or "kill" to do an
      immediate shutdown. Does not include a binary blob.
    * `CREATE_FILE_BEGIN` - Tells the backend to create a file in a sandbox.
      Introduces a new correlation ID. Takes five arguments; the UUID of the
      sandbox to write a file into, the owning user, the owning group, the
      file permissions (as an octal string), and the absolute path to save the
      file at. Does not include a binary blob.
    * `CREATE_FILE_BLOCK` - Sends the backend a block of a file being written.
      Must be correlated to a `CREATE_FILE_BEGIN` message. Takes no arguments.
      Includes a binary blob, the block of data to write to the file.
    * `CREATE_FILE_END` - Tells the backend that the file being written has
      been entirely sent. Must be correlated to a `CREATE_FILE_BEGIN` message.
      Takes no arguments. Does not include a binary blob.
    * `CREATE_DIR` - Tells the backend to create a directory in a sandbox.
      Introduces a new correlation ID. Takes five arguments; the UUID of the
      sandbox to create a directory in, the owning user, the owning group, the
      directory permissions (as an octal string), and the path to create the
      directory at. Does not include a binary blob.
    * `LIST_DIR` - Tells the backend to send back a listing of all file system
      objects in the specified directory. Introduces a new correlation ID.
      Takes two arguments; the UUID of the sandbox to get a listing from, and
      the path of the directory to list. Does not include a binary blob.
    * `READ_FILE` - Tells the backend to stream a file from the sandbox to the
      frontend. Introduces a new correlation ID. Takes two arguments, the UUID
      of the sandbox to read the file from, and the path to the file to read.
      Does not include a binary blob.
    * `READ_FILE_ABORT` - Tells the backend to stop streaming a file from a
      sandbox to the frontend. Must be correlated to a `READ_FILE` message.
      Takes no arguments. Does not include a binary blob.
    * `LIST_APPS` - Asks the backend to send the client a list of applications
      available in the sandbox. Introduces a new correlation ID. Takes one
      argument; the UUID of the sandbox to list the apps of. Does not include
      a binary blob.
    * `GET_APP_INFO` - Asks the backend to send the client information about
      an application in the sandbox. Introduces a new correlation ID. Takes
      two arguments; the UUID of the sandbox to get app info from, and the
      name of the desktop file containing the application definition in the
      sandbox. Does not include a binary blob.
    * `EXEC` - Tells the backend to launch an application in the sandbox.
      Introduces a new correlation ID. Takes two arguments; the UUID of the
      sandbox to launch an application within, and the name of the desktop file
      corresponding to the program to launch.  Includes a binary blob, a list
      of NULL-terminated file arguments to pass to the desktop file.
    * `SHELL` - Tells the backend to connect the frontend to the sandbox's
      console. Raw, unsanitized bytes will be piped between the sandbox and
      the frontend, it is the frontend's responsibility to do any necessary
      sanitization. Introduces a new correlation ID. Takes one argument, the
      UUID of the sandbox to shell into. Does not include a binary blob.
    * `SHELL_HS_BLOCK` - Provides a block of data to the backend to pipe into
      the sandbox shell. Must be correlated to a `SHELL` message. Takes no
      arguments.  Includes a binary blob, the block of data.
    * `SHELL_DISCONNECT` - Informs the backend that the frontend is
      disconnecting from the sandbox's shell. Must be correlated to a `SHELL`
      message. Takes no arguments. Does not include a binary blob.
  * Sent from server to client:
    * `CONFIRM_NEED_RESTART` - Informs the frontend that the backend needs
      restarted to apply pending software updates. Must be correlated to a
      client-sent `QUERY_NEED_RESTART`. Takes no arguments. Does not include a
      binary blob.
      * Implementation note, the server should wait to sent
        `CONFIRM_NEED_RESTART` until *after* it has sent information about the
        the current state of sandboxes on the system. This will allow the
        frontend to warn about the risk of shutting down running sandboxes and
        interrupting running jobs.
    * `DENY_NEED_RESTART` - Informs the frontend that the backend does not
      need to be restarted. Must be correlated to a client-sent
      `QUERY_NEED_RESTART` message. Takes no arguments. Does not include a
      binary blob.
    * `RESTART_INPROGRESS` - Informs the frontend that the restart request has
      been accepted and is being processed. Broadcast to all clients whether
      long-lived or not, this must also be broadcast to clients running under
      users other than the user that triggered it. Must be correlated to a
      client-sent `RESTART` message. Takes no arguments. Does not include a
      binary blob.
      * Note that there is no `RESTART_SUCCESS` message; the server will
        disconnect all clients for all users after sending this.
    * `RESTART_DENIED` - Informs the frontend that the restart request has
      been rejected. Must be correlated to a client-sent `RESTART` message.
      Takes no arguments. Does not include a binary blob.
    * `DUP_NAME` - Informs the frontend that the requested sandbox name
      is the same as an existing sandbox name. Must be correlated to a
      client-sent `CREATE_END`, `CONFIG_END`, or `CLONE` message. Takes no
      arguments. Does not include a binary blob.
    * `SANDBOX_RUNNING` - Informs the frontend that a sandbox is already
      running. Must be correlated to a client-sent `CONFIG_END`, `DELETE`,
      `CLONE`, or `BOOT` message. Takes no arguments. Does not include a binary
      blob.
    * `SANDBOX_NOT_RUNNING` - Informs the frontend that a sandbox is not
      running. Must be correlated to a `SHUTDOWN`, `CREATE_FILE_BEGIN`,
      `CREATE_DIR`, `LIST_DIR`, `READ_FILE`, `LIST_APPS`, `GET_APP_INFO`,
      `EXEC`, or `SHELL` message.
    * `SANDBOX_MISSING` - Informs the frontend that a sandbox cannot be found.
      Must be correlated to a client-sent message that refers to an existing
      sandbox (there are too many of these to enumerate easily here). Takes no
      arguments. Does not include a binary blob.
    * `CONFIG_INVALID` - Informs the frontend that the configuration
      information it sent when configuring a sandbox was invalid for some
      reason. Must be correlated to a client-sent `CREATE_END` or `CONFIG_END`
      message. Takes no arguments.  Does not include a binary blob.
    * `FSO_MISSING` - Informs the frontend that a source filesystem object
      does not exist. Must be correlated to a client-sent `READ_FILE`,
      `LIST_DIR`, or `EXEC` message. Takes no arguments.  Does not include a
      binary blob.
    * `FSO_EXISTS` - Informs the frontend that a target filesystem object
      already exists. Must be correlated to a client-sent `CREATE_FILE_BEGIN`
      or `CREATE_DIR` message. Takes no arguments. Does not include a binary
      blob.
    * `DAMAGED_SANDBOXES_START` - Informs the frontend that damaged sandboxes
      belonging to its user account are present. Introduces a new correlation
      ID. Takes no arguments. Does not include a binary blob.
    * `DAMAGED_SANDBOX` - Provides information about a damaged sandbox to the
      frontend. Must be correlated to a a `DAMAGED_SANDBOXES_START` message.
      Takes two arguments; the path to the damaged sandbox, and the name of
      the damaged sandbox (or the special string `<unknown>` if the sandbox's
      name is missing). Does not include a binary blob.
    * `DAMAGED_SANDBOXES_END` - Informs the frontend that info about all
      damaged sandboxes belonging to its user account has been sent. Must be
      correlated to a `DAMAGED_SANDBOXES_START` message. Takes no arguments.
      Does not include a binary blob.
    * `CREATE_INPROGRESS` - Informs the frontend that the sandbox creation
      request has been accepted and is being processed. Broadcast to
      long-lived clients. Must be correlated to a client-sent `CREATE_END`
      message when sent to the provoking client, introduces a new correlation
      ID otherwise. Takes one argument; the UUID of the new sandbox. Does not
      include a binary blob.
      * Implementation note, after sending this, but before sending one of
        `CREATE_SUCCESS` or `CREATE_FAILED`, the backend must send
        `CONFIG_INFO_START`, the config info of the new sandbox, and
        `CONFIG_INFO_END`.
    * `CREATE_SUCCESS` - Informs the frontend that a sandbox has been
      successfully created. Broadcast to long-lived clients. Must be
      correlated to a `CREATE_INPROGRESS` message. Takes no arguments. Does
      not include a binary blob.
    * `CREATE_FAILED` - Informs the frontend that a sandbox could not be
      created. Broadcast to long-lived clients.  Must be correlated to a
      `CREATE_INPROGRESS` message. Takes no arguments.  Does not include a
      binary blob.
    * `CONFIG_INPROGRESS` - Informs the frontend that the sandbox
      configuration request has been accepted and is being processed.
      Broadcast to all long-lived clients from the applicable user. Must be
      correlated to a client-sent `CONFIG_END` message when sent to the
      provoking client, introduces a new correlation ID otherwise. Takes one
      argument; the UUID of the sandbox being configured. Does not include a
      binary blob.
      * Implementation note, after sending this, but before sending one of
        `CONFIG_SUCCESS` or `CONFIG_FAILED`, the backend must send
        `CONFIG_INFO_START`, the new config info of the sandbox, and
        `CONFIG_INFO_END`.
    * `CONFIG_SUCCESS` - Informs the frontend that a sandbox has been
      successfully reconfigured. Broadcast to long-lived clients. Must be
      correlated to a `CONFIG_INPROGRESS` message. Takes no arguments. Does
      not include a binary blob.
    * `CONFIG_FAILED` - Informs the frontend that a sandbox could not be
      reconfigured. Broadcast to long-lived clients. Must be correlated to a
      `CONFIG_INPROGRESS` message. Takes no arguments.  Does not include a
      binary blob.
    * `CONFIG_INFO_START` - Informs the frontend that messages defining a
      sandbox's configuration are about to be sent. Broadcast to long-lived
      clients if correlated to a `CREATE_INPROGRESS` or `CONFIG_INPROGRESS`
      message. Must be correlated to a `CREATE_INPROGRESS`,
      `CONFIG_INPROGRESS`, or client-sent `GET_CONFIG` message. Takes no
      arguments. Does not include a binary blob.
    * `CONFIG_INFO_END` - Informs the frontend that it is done sending
      messages defining a sandbox's configuration. Broadcast to long-lived
      clients. Must be correlated to a `CONFIG_INFO_START` message. Takes no
      arguments. Does not include a binary blob.
    * `DELETE_INPROGRESS` - Informs the frontend that the sandbox deletion
      request has been accepted and is being processed. Broadcast to
      long-lived clients. Must be correlated to a client-sent `DELETE` message
      when sent to the provoking client, introduces a new correlation ID
      otherwise. Takes one argument; the UUID of the sandbox being deleted.
      Does not include a binary blob.
    * `DELETE_SUCCESS` - Informs the frontend that a sandbox has been
      successfully deleted. Broadcast to long-lived clients. Must be
      correlated to a `DELETE_INPROGRESS` message. Takes no arguments.
      Does not include a binary blob.
    * `DELETE_FAILED` - Informs the frontend that attempting to delete a
      sandbox has failed. Broadcast to long-lived clients. Must be correlated
      to a `DELETE_INPROGRESS` message. Takes no arguments. Does not include a
      binary blob.
    * `CLONE_INPROGRESS` - Informs the frontend that the sandbox clone request
      has been accepted and is being processed. Broadcast to long-lived
      clients.  Must be correlated to a client-sent `CLONE` message when sent
      to the provoking client, introduces a new correlation ID otherwise. Takes
      three arguments; the UUID of the source sandbox, the UUID of the cloned
      sandbox, and the name of the cloned sandbox. Does not include a binary
      blob.
      * The reason for all the arguments is that a long-running client should
        be able to take the configuration of the source sandbox, duplicate
        that to get the configuration of the cloned sandbox, and then simply
        change the name of the cloned sandbox. Less UNIX socket I/O is needed
        that way.
    * `CLONE_SUCCESS` - Informs the frontend that a sandbox has been
      successfully cloned. Broadcast to long-lived clients. Must be correlated
      to a `CLONE_INPROGRESS` message. Takes no arguments. Does not include a
      binary blob.
    * `CLONE_FAILED` - Informs the frontend that a sandbox could not be
      cloned. Broadcast to long-lived clients. Must be correlated to a
      `CLONE_INPROGRESS` message. Takes no arguments. Does not include a binary
      blob.
    * `BOOT_INPROGRESS` - Informs the frontend that the boot request has been
      accepted and is being processed. Broadcast to long-lived clients. Must
      be correlated to a client-sent `BOOT` message when sent to the provoking
      client, introduces a new correlation ID otherwise. Takes two arguments;
      the UUID of the sandbox being booted, and the mode being booted in
      (either "work" or "update"). Does not include a binary blob.
    * `BOOT_SUCCESS` - Informs the frontend that a sandbox has been
      successfully booted. Broadcast to long-lived clients. Must be correlated
      to a `BOOT_INPROGRESS` message. Takes no arguments. Does not include a
      binary blob.
    * `BOOT_FAILED` - Informs the frontend that attempting to boot a sandbox
      has failed. Broadcast to long-lived clients. Must be correlated to a
      `BOOT_INPROGRESS` message.  Takes no arguments. Does not include a
      binary blob.
    * `SHUTDOWN_INPROGRESS` - Informs the frontend that the shutdown request
      has been accepted and is being processed. Broadcast to long-lived
      clients. Must be correlated to a `SHUTDOWN` message when sent to the
      provoking client, introduces a new correlation ID otherwise. Takes two
      arguments; the UUID of the sandbox being shut down, and the shutdown
      mode being used ("shutdown" or "kill"). Does not include a binary blob.
    * `SHUTDOWN_SUCCESS` - Informs the frontend that a sandbox has been shut
      down. Broadcast to long-lived clients. Must be correlated to a
      `SHUTDOWN_INPROGRESS` message. Takes no arguments. Does not include a
      binary blob.
    * `SHUTDOWN_FAILED` - Informs the frontend that attempting to shut down a
      sandbox has failed. Broadcast to long-lived clients. Must be correlated
      to a `SHUTDOWN_INPROGRESS` message. Takes no arguments. Does not include
      a binary blob.
    * `CREATE_FILE_ACK` - Informs the frontend that the file creation request
      has been accepted and the backend is ready to receive file data. Must be
      correlated to a client-sent `CREATE_FILE_BEGIN` message. Takes no
      arguments. Does not include a binary blob.
    * `CREATE_FILE_SUCCESS` - Informs the frontend that the file was
      successfully created. Must be correlated to a `CREATE_FILE_ACK` message.
      Takes no arguments. Does not include a binary blob.
    * `CREATE_FILE_FAILED` - Informs the frontend that the file creation
      operation failed, either immediately or midway through. Must be
      correlated to a `CREATE_FILE_ACK` or client-sent `CREATE_FILE_BEGIN`
      message. Takes no arguments. Includes a binary blob, an error message to
      display to the end-user. This error message is untrusted and **MUST** be
      sanitized by the frontend before displaying it.
      * The error message is untrusted because sandbox-manager-dist uses a
        sandbox-side agent to handle part of file transfer, and malware make
        take over that agent and make it sent a malicious error message.
    * `CREATE_DIR_SUCCESS` - Informs the frontend that the directory was
      successfully created. Must be correlated to a client-sent `CREATE_DIR`
      message. Takes no arguments. Does not include a binary blob.
    * `CREATE_DIR_FAILED` - Informs the frontend that the directory could not
      be created. Must be correlated to a client-sent `CREATE_DIR` message.
      Takes no arguments. Includes a binary blob, an error message to display
      to the end-user. This error message is untrusted and **MUST** be
      sanitized by the frontend before displaying it.
      * See `CREATE_FILE_FAILED`  above.
    * `LIST_DIR_START` - Informs the frontend that messages defining a
      directory's metadata and its directory listing are about to be sent.
      Must be correlated to a client-sent `LIST_DIR` message. Takes no
      arguments. Does not include a binary blob.
    * `LIST_DIR_ENTRY` - Defines one entry in a directory listing. Must be
      correlated to a `LIST_DIR_START` message. Takes five arguments; an "f"
      or "d" depending on whether the entry is for a file or a directory, the
      object's owning user, the object's owning group, the object's permissions
      (as an octal string), and the name of the object. Does not include a
      binary blob.
    * `LIST_DIR_END` - Informs the frontend that it is done sending messages
      defining a directory listing. Must be correlated to a `LIST_DIR_START`
      message. Takes no arguments. Does not include a binary blob.
    * `LIST_DIR_FAILED` - Informs the frontend that listing a directory failed,
      either immediately or mid-way through. Must be correlated to a
      `LIST_DIR_START` or client-sent `LIST_DIR` message. Takes no arguments.
      Does not include a binary blob.
    * `READ_FILE_START` - Informs the frontend that the backend is about to
      send a file to it. Must be correlated to a client-sent `READ_FILE`
      message. Takes three arguments; the file's owning user, owning group,
      and the file permissions (as an octal string). Does not include a binary
      blob.
    * `READ_FILE_BLOCK` - Sends the frontend a block of a file being copied.
      Must be correlated to a `READ_FILE_START` message. Takes no arguments.
      Includes a binary blob, the block of data read from the file.
    * `READ_FILE_END` - Informs the frontend that the file being read has been
      entirely sent. Must be correlated to a `READ_FILE_START` message. Takes
      no arguments. Does not include a binary blob.
    * `READ_FILE_ABORT_ACK` - Informs the frontend that a `READ_FILE_ABORT`
      message has been accepted and it should not expect a `READ_FILE_END`
      message. Must be correlated to a client-sent `READ_FILE_ABORT` message.
      Takes no arguments. Does not include a binary blob.
    * `READ_FILE_FAILED` - Informs the frontend that the file read operation
      failed, either immediately or midway through. Must be correlated to a
      `READ_FILE_START` or client-sent `READ_FILE` message. Takes no
      arguments. Includes a binary blob, an error message to display to the
      end-user.  This error message is untrusted and **MUST** be sanitized by
      the frontend before displaying it.
      * See `CREATE_FILE_FAILED` above.
    * `LIST_APPS_START` - Informs the frontend that an application list is
      about to be sent. Must be correlated to a client-sent `LIST_APPS`
      message. Takes no arguments. Does not include a binary blob.
    * `LIST_APPS_ENTRY` - Defines an application in a sandbox. Must be
      correlated to a `LIST_APPS_START` message. Takes three arguments; the
      application category, the application name, and the name of the desktop
      file defining the application. Does not include a binary blob.
    * `LIST_APPS_END` - Informs the frontend that an application list has been
      sent. Must be correlated to a `LIST_APPS_START` message. Takes no
      arguments. Does not include a binary blob.
    * `LIST_APPS_FAILED` - Informs the frontend that the app listing operation
      failed, either immediately or midway through. Must be correlated to a
      `LIST_APPS_START` or client-sent `LIST_APPS` message. Takes no arguments.
      Includes a binary blob, an error message to display to the end-user. This
      error message is untrusted and **MUST** be sanitized by the frontend
      before displaying it.
      * See `CREATE_FILE_FAILED` above.
    * `GET_APP_INFO_START` - Informs the frontend that messages defining an
      application's info are about to be sent. Must be correlated to a
      client-sent `GET_APP_INFO` message. Takes no arguments. Does not include
      a binary blob.
    * `APP_INFO_NAME` - Specifies the name of an application. Must be
      correlated to a `GET_APP_INFO_START` message. Takes one argument, the
      application name. Does not include a binary blob.
    * `APP_INFO_GENERIC_NAME` - Specifies the generic name of an application.
      Must be correlated to a `GET_APP_INFO_START` message. Takes one
      argument, the app description. Does not include a binary blob.
    * `APP_INFO_COMMENT` - Specifies an application comment. Must be
      correlated to a `GET_APP_INFO_START` message. Takes one argument, the
      comment string. Does not include a binary blob.
    * `APP_INFO_EXEC` - Specifies the execution information (environment
      variables, program, arguments) for an application. Must be correlated to
      a `GET_APP_INFO_START` message. Takes one argument, the execution string.
      Does not include a binary blob.
    * `APP_INFO_WORK_DIR` - Specifies the working directory of the program
      providing an application. Must be correlated to a `GET_APP_INFO_START`
      message. Takes one argument, the working dir path. Does not include a
      binary blob.
    * `APP_INFO_MIMETYPE` - Specifies a MIME type the application is able to
      handle. Must be correlated to a `GET_APP_INFO_START` message. Takes one
      argument, the MIME type string. Does not include a binary blob.
    * `GET_APP_INFO_END` - Informs the frontend that application info is done
      being sent.  Must be correlated to a `GET_APP_INFO_START` message. Takes
      no arguments. Does not include a binary blob.
    * `GET_APP_INFO_FAILED` - Informs the frontend that the application info
      fetch operation failed, either immediately or mid-way through.  Must be
      correlated to a `GET_APP_INFO_START` or client-sent `GET_APP_INFO`
      message. Takes no arguments. Does not include a binary blob.
    * `EXEC_SUCCESS` - Informs the frontend that executing an application has
      succeeded. Must be correlated to a client-sent `EXEC` message. Takes no
      arguments. Does not include a binary blob.
    * `EXEC_FAILED` - Informs the frontend that executing an application has
      failed. Must be correlated to a client-sent `EXEC` message. Takes no
      arguments. Does not include a binary blob.
    * `SHELL_ACK` - Informs the client that the request to open the sandbox's
      shell has been accepted and the backend is now ready to exchange shell
      bytes with the client. Must be correlated to a client-sent `SHELL`
      message. Takes no arguments. Does not include a binary blob.
    * `SHELL_SB_BLOCK` - Provides a block of data to the frontend that came
      from the sandbox shell. Must be correlated to a `SHELL_ACK` message.
      Takes no arguments. Includes a binary blob, the block of data.
    * `SHELL_DISCONNECTED` - Informs the client that its connection to the
      sandbox's shell has been disconnected. Must be correlated to a
      `SHELL_ACK` or client-sent `SHELL_DISCONNECT` message. Takes no
      arguments. Does not include a binary blob.
    * `SHELL_FAILED` - Informs the client that the sandbox's shell could not
      be opened. Must be correlated to a client-sent `SHELL` message. Takes no
      arguments. Does not include a binary blob.
  * Sent in either direction, as needed, all of these must be correlated to a
    `CREATE_START`, `CONFIG_START`, or `CONFIG_INFO_START` message, will be
    broadcast to long-running clients if the correlated message is broadcast:
    * `NAME` - Specifies the name of a sandbox. Takes one argument, the name
      of the sandbox. Does not include a binary blob.
    * `DESCRIPTION` - Specifies the description of a sandbox. Takes one
      argument; the sandbox description. Does not include a binary blob.
    * `ROOT_VOL_SIZE` - Specifies the size of the sandbox's root volume, in
      bytes. The maximum root volume size is currently 16 TiB - 4096 bytes.
      Takes one argument, the volume size. Does not include a binary blob.
    * `DATA_VOL_SIZE` - Specifies the size of the sandbox's data volume, in
      bytes. The maximum data volume size is currently 16 TiB - 4096 bytes.
      Takes one argument, the volume size. Does not include a binary blob.
    * `MEMORY` - Specifies the size of the sandbox's available RAM, in bytes.
      The maximum memory size is currently 1 TB. Takes one argument, the memory
      size. Does not include a binary blob.
    * `CPU_WEIGHT` - Specifies the CPU weight of the sandbox. The highest
      possible CPU weight is 10000. Takes one argument, the CPU weight. Does
      not include a binary blob.
    * `CPU_CORES` - Specifies the number of CPU cores the sandbox is
      allocated. Only supported for VM-based sandbox isolation. The highest
      possible core count is 256. Takes one argument, the core count. Does not
      include a binary blob.
    * `IO_WEIGHT` - Specifies the I/O weight of the sandbox.  The highest
      possible I/O weight is 10000. Takes one argument, the I/O weight. Does
      not include a binary blob.
    * `AUDIO_ENABLED` - Specifies whether the sandbox has access to the host's
      audio system. Takes one argument, "y" for "yes", and "n" for "no". Does
      not include a binary blob.
    * `WAYLAND_ENABLED` - Specifies whether the sandbox has access to the
      host's Wayland compositor. Takes one argument, "y" for "yes", and "n" for
      "no". Does not include a binary blob.
    * `X11_ENABLED` - Specifies whether the sandbox has access to the host's
      X11 server. Takes one argument, "y" for "yes", and "n" for "no". Does not
      include a binary blob.
    * `3D_ENABLED` - Specifies whether the sandbox has access to the host's
      graphics card. Takes one argument, "y" for "yes", and "n" for "no". Does
      not include a binary blob.
    * `NETWORK_ENABLED` - Specifies whether the sandbox has access to the
      network. Takes one argument, "y" for "yes", and "n" for "no". Does not
      include a binary blob.
    * `NESTED_SANDBOXING_ENABLED` - Specifies whether the sandbox allows nested
      sandboxing or not. Takes one argument, "y" for "yes", and "n" for "no".
      Does not include a binary blob.
    * `SHARED_FSO` - Specifies a folder or file shared from the host to the
      sandbox.  Takes three argument; "RW" or "RO" indicating whether the
      sandbox should be able to write to the file or folder on the host, the
      path of the file or folder on the host, and the path of the file or
      folder within the sandbox. Does not include a binary blob.
    * `SHARED_DEVICE` - Specifies a device shared from the host to the sandbox.
      Takes one arguments; the path to the device being shared. Does not
      include a binary blob.
  * Intentionally omitted commands one might expect to be present:
    * `PIN_APP`, `UNPIN_APP` - This functionality is going to be implemented
      entirely on the client side, the backend doesn't need to be involved.
    * `SYNC_ACK` - There is no need for the client to be explicitly told that
      its registering of itself as a long-running client has succeeded.
* The agent protocol is identical to the comm protocol, but not all messages
  are supported, the backend uses the commands the frontend would normally use,
  and the agent uses the commands the backend would normally use. The following
  messages are part of the agent protocol:
  * Sent from backend to agent:
    * `CREATE_FILE_BEGIN`
    * `CREATE_FILE_BLOCK`
    * `CREATE_FILE_END`
    * `CREATE_DIR`
    * `LIST_DIR`
    * `READ_FILE`
    * `READ_FILE_ABORT`
    * `LIST_APPS`
    * `GET_APP_INFO`
    * `EXEC`
  * Send from agent to backend:
    * `FSO_MISSING`
    * `FSO_EXISTS`
    * `CREATE_FILE_ACK`
    * `CREATE_FILE_FAILED`
    * `CREATE_FILE_SUCCESS`
    * `CREATE_DIR_SUCCESS`
    * `CREATE_DIR_FAILED`
    * `LIST_DIR_START`
    * `LIST_DIR_ENTRY`
    * `LIST_DIR_END`
    * `LIST_DIR_FAILED`
    * `READ_FILE_START`
    * `READ_FILE_BLOCK`
    * `READ_FILE_END`
    * `READ_FILE_ABORT_ACK`
    * `READ_FILE_FAILED`
    * `LIST_APPS_START`
    * `LIST_APPS_ENTRY`
    * `LIST_APPS_END`
    * `LIST_APPS_FAILED`
    * `GET_APP_INFO_START`
    * `APP_INFO_NAME`
    * `APP_INFO_DESCRIPTION`
    * `APP_INFO_COMMENT`
    * `APP_INFO_ENVIRONMENT`
    * `APP_INFO_PROGRAM`
    * `APP_INFO_ARGUMENTS`
    * `APP_INFO_WORK_DIR`
    * `APP_INFO_MIMETYPE`
    * `GET_APP_INFO_END`
    * `GET_APP_INFO_FAILED`
    * `EXEC_SUCCESS`
    * `EXEC_FAILED`

# Possible future features:

* Allow restricting in-container capabilities (if disabled, no-new-privileges
  flag is set and capabilities are dropped except those needed for boot)
* Audio access, restrict camera and mic separately
* Wayland access, allow restricting dangerous protocols like emulated input and
  screen capture (this probably will never be done)
* High-security mode, run a Wayland compositor within the sandbox itself and
  connect to it over VNC
  * This one might be a higher priority
  * Future goal for this, allow virtualizing audio too, the first iteration
    will probably not have this
* Add a VM-isolated sandboxing mode that uses systemd-vmspawn
  * systemd-vmspawn does not support a "live mode", so we would have to create
    something to support that ourselves if we added vmspawn support.  vmspawn
    would also potentially replace "CPU weight" with "CPU cores", might lose
    I/O weight support, cannot use accelerated graphics, and cannot use shared
    devices.  Audio, Wayland, X11 integration, installed application detection,
    and launching of specific applications can probably be done using vsock
    networking.
  * Waypipe can be used to give Wayland apps access to the host compositor,
    but this actually increases the attack surface beyond the already large
    attack surface present when allowing apps to connect directly to a
    compositor. See
    https://man.archlinux.org/man/extra/waypipe/waypipe.1.en#SECURITY. While
    it is arch-specific code, it might (?) be more secure and still
    semi-practical to rip off Google's Sommelier compositor
    (https://man.archlinux.org/man/extra/waypipe/waypipe.1.en#SECURITY) and
    use that instead.
  * We should still try to design this with the features of systemd-vmspawn in
    mind for in the future.
  * We might be able to implement this even without systemd-vmspawn if we are
    willing to use QEMU directly. systemd-vmspawn is itself a QEMU wrapper,
    and it isn't all that similar to systemd-nspawn, so this might not be
    unreasonable.
