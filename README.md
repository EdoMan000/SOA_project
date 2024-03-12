# SOA_project

The examination requires fulfilling the development of a project in the Linux kernel, which must comply with the following specification.

### Kernel Level Reference Monitor for File Protection
This specification is related to a $Linux Kernel Module (LKM)$ implementing a reference monitor for file protection. The reference monitor can be in one of the following four states:
- $OFF$, meaning that its operations are currently disabled;
- $ON$, meaning that its operations are currently enabled;
- $REC-ON/REC-OFF$, meaning that it can be currently reconfigured (in either ON or OFF mode).
The configuration of the reference monitor is based on a set of file system paths. Each path corresponds to a file/dir that cannot be currently opened in write mode. Hence, any attempt to write-open the path needs to return an error, independently of the user-id that attempts the open operation.

Reconfiguring the reference monitor means that some path to be protected can be added/removed. In any case, changing the current state of the reference monitor requires that the thread that is running this operation needs to be marked with effective-user-id set to root, and additionally the reconfiguration requires in input a password that is reference-monitor specific. This means that the encrypted version of the password is maintained at the level of the reference monitor architecture for performing the required checks.

It is up to the software designer to determine if the above states ON/OFF/REC-ON/REC-OFF can be changed via VFS API or via specific system-calls. The same is true for the services that implement each reconfiguration step (addition/deletion of paths to be checked). Together with kernel level stuff, the project should also deliver user space code/commands for invoking the system level API with correct parameters.

In addition to the above specifics, the project should also include the realization of a file system where a single append-only file should record the following tuple of data (per line of the file) each time an attempt to write-open a protected file system path is attempted:

the process TGID <br>
the thread ID <br>
the user-id <br>
the effective user-id <br>
the program path-name that is currently attempting the open <br>
a cryptographic hash of the program file content <br>
The computation of the cryptographic hash and the writing of the above tuple should be carried in deferred work. <br>

$NB:]$  Try to manage hard links to files and include them in the security mechanism