# SOA_project 
## | Kernel Level Reference Monitor for File Protection | 

The examination requires fulfilling the development of a project in the Linux kernel.

> [!NOTE] 
> The official specification can be found at [The project specification](https://francescoquaglia.github.io/TEACHING/AOS/CURRENT/PROJECTS/project-specification-2023-2024.html)

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
> All of the code was developed and tested on kernel version 
> - 6.5.0-26-generic
> - 6.2.0-34-generic 
> - 5.15.0-25-generic.

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
   make tool
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