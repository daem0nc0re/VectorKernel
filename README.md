# VectorKernel

PoCs for Kernelmode rootkit techniques research or education.
Currently focusing on Windows OS.
All modules support x64 family 64bit OS only.


## Environment

All modules are tested in Windows 11 x64.
To test drivers, following options can be used for the testing machine:

1. [Enable Loading of Test Signed Drivers](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/the-testsigning-boot-configuration-option)

2. [Setting Up Kernel-Mode Debugging](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/setting-up-kernel-mode-debugging-in-windbg--cdb--or-ntsd)

Each options require to disable secure boot.


## Modules

Detailed information is given in README.md in each project's directories.
All modules are tested in Windows 11.

| Module Name | Description |
| :--- | :--- |
| [BlockImageLoad](./BlockImageLoad/) | PoCs to block driver loading with Load Image Notify Callback method. |
| [BlockNewProc](./BlockNewProc/) | PoCs to block new process with Process Notify Callback method. |
| [CreateToken](./CreateToken/) | PoCs to get full privileged SYSTEM token with `ZwCreateToken()` API. |
| [DropProcAccess](./DropProcAccess/) | PoCs to drop process handle access with Object Notify Callback. |
| [ElevateHandle](./ElevateHandle/) | PoCs to elevate handle access with DKOM method. |
| [GetFullPrivs](./GetFullPrivs/) | PoCs to get full privileges with DKOM method. |
| [GetProcHandle](./GetProcHandle/) | PoCs to get full access process handle from kernelmode. |
| [InjectLibrary](./InjectLibrary/) | PoCs to perform DLL injection with Kernel APC Injection method. |
| [ModHide](./ModHide/) | PoCs to hide loaded kernel drivers with DKOM method. |
| [ProcHide](./ProcHide/) | PoCs to hide process with DKOM method. |
| [ProcProtect](./ProcProtect/) | PoCs to manipulate Protected Process. |
| [QueryModule](./QueryModule/) | PoCs to perform retrieving kernel driver loaded address information. |
| [StealToken](./StealToken/) | PoCs to perform token stealing from kernelmode. |


## TODO

More PoCs especially about following things will be added later:

* Notify callback
* Filesystem mini-filter
* Network mini-filter

## Recommended References

* [Pavel Yosifovich, **_Windows Kernel Programming, 2nd Edition_** (Independently published, 2023)](https://leanpub.com/windowskernelprogrammingsecondedition)

* [Bruce Dang, Alexandre Gazet, Elias Bachaalany, and Sébastien Josse, **_Practical Reverse Engineering: x86, x64, ARM, Windows Kernel, Reversing Tools, and Obfuscation_** (Wiley Publishing, 2014)](https://www.amazon.com/Practical-Reverse-Engineering-Reversing-Obfuscation/dp/1502489309)

* [Greg Hoglund, and Jamie Butler, **_Rootkits : Subverting the Windows Kernel_** (Addison-Wesley Professional, 2005)](https://www.amazon.com/Rootkits-Subverting-Windows-Greg-Hoglund/dp/0321294319)

* [Bill Blunden, **_The Rootkit Arsenal: Escape and Evasion in the Dark Corners of the System, 2nd Edition_** (Jones & Bartlett Learning, 2012)](https://www.amazon.com/Rootkit-Arsenal-Escape-Evasion-Corners/dp/144962636X)

* [Pavel Yosifovich, Mark E. Russinovich, Alex Ionescu, and David A. Solomon, **_Windows Internals, Part 1: System architecture, processes, threads, memory management, and more, 7th Edition_** (Microsoft Press, 2017)](https://www.microsoftpressstore.com/store/windows-internals-part-1-system-architecture-processes-9780735684188)

* [Andrea Allievi, Mark E. Russinovich, Alex Ionescu, and David A. Solomon, **_Windows Internals, Part 2, 7th Edition_** (Microsoft Press, 2021)](https://www.microsoftpressstore.com/store/windows-internals-part-2-9780135462409)

* [Matt Hand, **_Evading EDR - The Definitive Guide to Defeating Endpoint Detection Systems_** (No Starch Press, 2023)](https://nostarch.com/evading-edr)
