# SOA_project 
## | Kernel Level Reference Monitor for File Protection | 

The examination requires fulfilling the development of a project in the Linux kernel, which must comply with the following specification.

### Specification
This specification is related to a **$Linux Kernel Module (LKM)$** implementing a reference monitor for file protection. The reference monitor can be in one of the following four states:
- **OFF**, meaning that its operations are currently disabled;
- **ON**, meaning that its operations are currently enabled;
- **REC-ON/REC-OFF**, meaning that it can be currently reconfigured (in either ON or OFF mode).
The configuration of the reference monitor is based on a set of file system paths. Each path corresponds to a file/dir that cannot be currently opened in write mode. Hence, any attempt to write-open the path needs to return an error, independently of the user-id that attempts the open operation.

Reconfiguring the reference monitor means that some path to be protected can be added/removed. In any case, changing the current state of the reference monitor requires that the thread that is running this operation needs to be marked with effective-user-id set to root, and additionally the reconfiguration requires in input a password that is reference-monitor specific. This means that the encrypted version of the password is maintained at the level of the reference monitor architecture for performing the required checks.

It is up to the software designer to determine if the above states ON/OFF/REC-ON/REC-OFF can be changed via VFS API or via specific system-calls. The same is true for the services that implement each reconfiguration step (addition/deletion of paths to be checked). Together with kernel level stuff, the project should also deliver user space code/commands for invoking the system level API with correct parameters.

In addition to the above specifics, the project should also include the realization of a file system where a single append-only file should record the following tuple of data (per line of the file) each time an attempt to write-open a protected file system path is attempted:
- the process TGID <br>
- the thread ID <br>
- the user-id <br>
- the effective user-id <br>
- the program path-name that is currently attempting the open <br>
- a cryptographic hash of the program file content <br>

**NB:]** The computation of the cryptographic hash and the writing of the above tuple should be carried in deferred work. <br>

> [!NOTE] 
> Official documentation can be found at [The project specification](https://francescoquaglia.github.io/TEACHING/AOS/CURRENT/PROJECTS/project-specification-2023-2024.html)

# About the provided implementation of the reference-monitor module

## Included Parts
- **the_utscm module:** An embedded module leveraged by the reference-monitor module to discover the memory positioning of the Linux system_call_table.
- **scth:** A linux kernel lib  which implements the dynamc discovery of the position of the sys_call_table and the identifiction of entries pointing to sys_ni_syscall
- **singlefile-FS module:** A filesystem module that supports a single append-only file, modified by me to use it primarily for writing intrusion logs.
- **reference-monitor module:** the Linux Kernel Module which implements a reference monitor based on a set of file system paths, providing two new system calls.
- **Refmon Tool:** A simple CLI tool to interact with the refmon module, invoking its system calls.

> [!NOTE] 
> Credits for developing the first three go to [Francesco Quaglia](https://github.com/FrancescoQuaglia)

## Compile, Mount and Run!

This section provides a clear guide on how to install the modules, use the configuration tool, and clean up afterwards.

### Prerequisites
Before you begin, ensure you have the necessary development tools installed on your system. You will need the GCC compiler, make utility, and kernel headers for your Linux distribution. <br>
This guide assumes you have basic knowledge of compiling kernel modules and using Makefiles.<br>
> [!IMPORTANT] 
> All of the code was developed and tested on kernel version 6.5.0-26-generic.

### Compiling and mounting everything
1. Clone the repo in your local machine:
```shell
   git clone https://github.com/EdoMan000/SOA_project.git
   cd SOA_project
```

2. Using the provided "all in one" `Makefile` you can be up and running in seconds... <br> Just type:
```make
   make up
```

3. Run the **$Refmon Tool$** to access the CLI with:
```shell
   sudo ./refmon_tool_run
```
> [!TIP] 
> At this point follow the on-screen instructions to interact with the Reference Monitor. The tool provides a menu-driven interface to manage and reconfigure the Reference Monitor.

### Cleaning Up
Again, with a simple command it will all be like it never happened... <br> Just type:
```make
   make down
```

### Other make commands
If you want some sort of a slower process (i would ask you why) there still are some commands left:
```make
   make all
   make mount
   make unmount
   make clean
```
And also some commands to query, enable or disable reconfiguration of the reference monitor when it is mounted:
```make
   make check
   make enable
   make disable
```

> [!WARNING] 
> Some of the make commands provided above may ask you the [sudo] password to run privileged, make sure to provide it to avoid any problems. Remember also to run the tool with EUID 0 if you want to avoid that all your interactions fail due to permission denied.  