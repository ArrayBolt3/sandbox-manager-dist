# sandbox-manager-dist - Namespace-based environment isolation for Linux

sandbox-manager-dist is an application sandboxing system that focuses on
sandboxing environments rather than individual applications. Under the hood, it
is essentially a fancy frontend to systemd-nspawn, allowing one to create,
manage, and use per-use-case containers ("sandboxes") without requiring root
privileges. It provides some (but far from all) of the advantages of Qubes OS
without requiring virtualization features, allowing it to run apps with
reasonable performance even when running inside a true virtual machine.

## Rationale and Design

The rationale for creating sandbox-app-manager, and the initial design
concepts it implements, can be seen here:
https://forums.kicksecure.com/t/separate-some-user-applications-from-the-operating-system/1120

A far more detailed design document is present
[in this repo](sandbox-manager-dist-design.md).

## Testing

The test suite currently uses Debian's autopkgtest system. It is unfortunately
not possible to run the test suite on Qubes OS, as testing is done in a QEMU
virtual machine.

TODO: add testing steps here
