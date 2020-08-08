# PS4 5.05 - 6.72 Kernel Exploit
---
## Summary
In this project you will find a full implementation of the "ipv6 uaf" kernel exploit for the PlayStation 4 for firmwares 5.05 - 6.72. It will allow you to run arbitrary code as kernel, to allow jailbreaking and kernel-level modifications to the system. will launch the usual payload launcher (on port 9020).

This bug was originally discovered by [Fire30](https://twitter.com/fire30), and subsequently found by [Andy Nguyen](https://twitter.com/theflow0/)

## Implementations
* [5.05](https://github.com/ChendoChap/ps4-ipv6-uaf/tree/5.05)
* [5.50](https://github.com/ChendoChap/ps4-ipv6-uaf/tree/5.50)
* [5.53](https://github.com/ChendoChap/ps4-ipv6-uaf/tree/5.53)
* [5.55 - 5.56](https://github.com/ChendoChap/ps4-ipv6-uaf/tree/5.55-5.56)
* [6.00 - 6.02](https://github.com/ChendoChap/ps4-ipv6-uaf/tree/6.00-6.02)
* [6.20](https://github.com/ChendoChap/ps4-ipv6-uaf/tree/6.20)
* [6.50 - 6.51](https://github.com/ChendoChap/ps4-ipv6-uaf/tree/6.50-6.51)
* [6.70 - 6.72](https://github.com/ChendoChap/ps4-ipv6-uaf/tree/6.70-6.72)

## Patches Included
The following patches are applied to the kernel:
1) Allow RWX (read-write-execute) memory mapping (mmap / mprotect)
2) Syscall instruction allowed anywhere
3) Dynamic Resolving (`sys_dynlib_dlsym`) allowed from any process
4) Custom system call #11 (`kexec()`) to execute arbitrary code in kernel mode
5) Allow unprivileged users to call `setuid(0)` successfully. Works as a status check, doubles as a privilege escalation.

## Notes
- The page will crash on successful kernel exploitation, this is normal
- There are a few races involved with this exploit, losing one of them and attempting the exploit again might not immediately crash the system but stability will take a hit, upon seeing an '[ERROR] ...' alert it is best to reboot the system.
- 6.xx's webkit side is occasionally unstable atm and may trigger a 'few' extra OOM's
- the payload loader does not mmap at a static address, make sure payloads are made with this in mind.

## Contributors

- [Specter](https://twitter.com/SpecterDev) - advice + [5.05 webkit](https://github.com/Cryptogenic/PS4-5.05-Kernel-Exploit/blob/master/expl.js) and [(6.20) rop execution method](https://github.com/Cryptogenic/PS4-6.20-WebKit-Code-Execution-Exploit)
- [kiwidog](https://twitter.com/kd_tech_) - advice
- [Fire30](https://twitter.com/fire30) - [bad_hoist](https://github.com/Fire30/bad_hoist)
- [Andy Nguyen](https://twitter.com/theflow0/) - [disclosed exploit code](https://hackerone.com/reports/826026)
- [SocraticBliss](https://twitter.com/SocraticBliss) - Shakespeare dev & crash test dummy