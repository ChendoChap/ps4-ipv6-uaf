# PS4 7.00 - 7.02 Kernel Exploit
---
## Summary
In this project you will find a full implementation of the "ipv6 uaf" kernel exploit for the PlayStation 4 on 7.00 - 7.02. It will allow you to run arbitrary code as kernel, to allow jailbreaking and kernel-level modifications to the system. will launch the usual payload launcher (on port 9020).

This bug was originally discovered by [Fire30](https://twitter.com/fire30), and subsequently found by [Andy Nguyen](https://twitter.com/theflow0/)

## Patches Included
The following patches are applied to the kernel:
1) Allow RWX (read-write-execute) memory mapping (mmap / mprotect)
2) Syscall instruction allowed anywhere
3) Dynamic Resolving (`sys_dynlib_dlsym`) allowed from any process
4) Custom system call #11 (`kexec()`) to execute arbitrary code in kernel mode
5) Allow unprivileged users to call `setuid(0)` successfully. Works as a status check, doubles as a privilege escalation.
6) (`sys_dynlib_load_prx`) patch
## Notes
- The page will crash on successful kernel exploitation, this is normal
- There are a few races involved with this exploit, losing one of them and attempting the exploit again might not immediately crash the system but stability will take a hit.

## Contributors

- [Specter](https://twitter.com/SpecterDev) - advice + [5.05 webkit](https://github.com/Cryptogenic/PS4-5.05-Kernel-Exploit/blob/master/expl.js) and [(6.20) rop execution method](https://github.com/Cryptogenic/PS4-6.20-WebKit-Code-Execution-Exploit)
- [kiwidog](https://twitter.com/kd_tech_) - advice
- [Fire30](https://twitter.com/fire30) - [bad_hoist](https://github.com/Fire30/bad_hoist)
- [Andy Nguyen](https://twitter.com/theflow0/) - [disclosed exploit code](https://hackerone.com/reports/826026)
- [SocraticBliss](https://twitter.com/SocraticBliss) - Shakespeare dev & crash test dummy
- [Znullptr](https://twitter.com/Znullptr) - drunk.dev
- [synacktiv](https://www.synacktiv.com) - [webkit exploit](https://www.synacktiv.com/publications/this-is-for-the-pwners-exploiting-a-webkit-0-day-in-playstation-4.html)
- [sleirsgoevy](https://twitter.com/sleirsgoevy) - ^ ported webkit exploit to 7.02 (and add addrof js prim)