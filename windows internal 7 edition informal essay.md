[original book pdf version -- part I](https://github.com/wqreytuk/article/blob/main/Windows%20System%20Internals%207e%20Part%201(1).pdf)

[original book pdf version -- part II](https://github.com/wqreytuk/article/blob/main/Windows%20Internals%20Part%202%207Ed.pdf)


you know, windows is written by C, and there is no conception like namespace,
so the function name is just a complete mess

then COM is introduced 

COM is originally created to serve MS office product, to make different type document
to communicate with, such as embedding an excel or ppt in word -- this ability is
call OLE -- Object Linking and Embedding

OLE is originally implemented using an old Windows messaging mechanism called
Dynamic Data Exchange -- DDE

DDE is limited enherently, so COM is created to replace it, in fact, COM's original
name is OLE2

here are two foundational principals:
 - client communicates with object through interface, the interface here represents
   well-defined contracts with a set of logically related methods grouped under the 
   virtual table dispatch machanism, this is also a common way for C++ compiles to implem-
   ents virtual functions dispatch
   this makes binaries compatible and compiler name mangling issues are removed, which
   makes it possible to call these methods from many other languages, such as C, C++
   VB, .NET, Delphi, etc...
 - component implementation is loaded dynamically rather than being statically linked to client
 
you may often see the term `COM server`, it typically refers to a DLL -- Dynamic Linked Library
or an EXE -- Executable where the COM classes are implemented

I always see the term `Marshalling`, but I never know what does it mean, today I googled it:
 - In computer science, marshalling or marshaling (US spelling) 
   is the process of transforming the memory representation of an object into a data format 
   suitable for storage or transmission
   It is typically used when data must be moved between different parts of a computer program
   or from one program to another
   
in a word, marshalling is object transition

Windows Runtime

Win8 introduced a new API which supporting runtime called Windows Runtime -- WinRT
do not be confused with Windows RT, Windows RT is a build of operate system, which running on
ARM processor, and this build didn't last for a long time

WinRT consists of platform services aimed particularly at app developers for the so-called
Windows Apps (formerly known as Metro Apps, Modern Apps, Immersive Apps and Windows Store Apps)

from an API perspective, WinRT is built on top of COM, by adding various extensions to the
base COM infrastructure

but at the basic binary level, WinRT API is still based on top of the legacy winndows binaries and
APIs, even the availability of certain APIs may not be documented or supported, it is not a new `native`
API for the OS, .NET still leverages the traditional Windows API

The .NET Framework

here is a table for different OS build's default .NET version

![image](https://user-images.githubusercontent.com/48377190/190040521-2267c37a-86f3-4232-86c7-bb8968dd6ce9.png)

there are two major components:
 - CLR -- Common Language Runtime, this is the run-time engine for .NET and a Just In Time -- JIT compiler is included
   in, this compiler will translate Common Intermediate Language -- CIL instructions to the underlying hardware CPU
   machine language, and a grabage collector is included, too
   CLR is implemented as a COM in-process server (DLL) and it uses various facilities provided by the Windows API
 - FCL -- .NET Framework Class Library, this is a large collection of types that implement functionality typically nedded
   by client and server applications, such as user interface services, networking, database access and much more
   
   
here is an illustration for the relationship between the .NET framework and the OS:

![image](https://user-images.githubusercontent.com/48377190/190041803-0ddfb8cc-b5bf-4366-8ce0-2b6a8aedf12f.png)

Services, functions and routines

several terms in the Windows user and programming doc have different meanings in different contexts, this is im-
portant, I used to be confused about it

for example, the word `service` can refer to a callable routine  is the OS, a device driver, or a server process

Processes

here is the essential difference between program and process, former is a static sequence of instructions,
and latter is a container for a set of resources used when executing the instance of the program

at the highest level of abstraction, a windows process comprises the following:
 - A private virtual address space
 - An executable program
 - A list of open handles
 - A securitty context, an access token used to identify the user, security groups, privileges, attributes, claims
   capabilities, User Account Control (UAC) virtualization state, session, and limited user account state associated
   with the process, as well as the AppContainer identifier and its related sandboxing information
 - A process ID
 - At least one thread of execution, `empty` (no thread) process is allowed, although it's useless, it can exist

there are plenty of tools to view information of process, the most popular of them is task manager, which
is built with windows OS, but there is no such thing as `Task` in windows kernel, so it is a bit odd to call
it `Task Manager`

so there is a hot key `Ctrl+Shift+Esc` to start taskmgr.exe, I used to open it with Ctrl+Alt+Del, and then click
`TaskmManager`, didn't even know there is a hot key for itself

there is only parent-child relationship in windows, no grandparent, there is no link between grandparent and child
check this video: https://youtu.be/tmgPBP3wr7k

with Process Explorer, we can get more information about process and thread than built-in taskmgr.exe

 - A process security token
 - Highlighting to show changes in the process, thread, DLLs and handles list
 - ...
 - the ability to suspend a process or thread
 - the ability to kill an individual thread
 - ...

viewing process details with [Process Explorer](https://github.com/wqreytuk/article/blob/main/ProcessExplorer.zip)

first, we'll need to configure symbol path, just like using windbg:

![image](https://user-images.githubusercontent.com/48377190/190069959-778248ac-b6f9-4da2-9f99-cb5a9a758378.png)

![image](https://user-images.githubusercontent.com/48377190/190070120-49512e86-423c-4af9-b4cc-13820a72d55b.png)

just configure environment variable `_NT_SYMBOL_PATH` is enough, different tools will check this env variable to
get symbol path automatically

I did learn something about ProcExp


Threads

**A thread is an entity within a process that windows schedules for execution**

here is the essential components of thread:
 - The contents of a set of CPU registers representing the state of the processor
 - Two stacks -- one for the thread to use while executing in kernel mode and one for user mode
 - A private storage area called `thread-local storage (TLS)` for use by subsystems, run-tim libraries 
   and DLLs
 - Thread ID

in addition, threads sometimes have their own security context, this is mainly used by multithread server
apps that impersonate the security context of the clients that they serve

the volatile registers, stacks and private storage area are called the thread's `context`

`context` is differnet between different architecture that Windows runs on, so it is architecture-specific,
we can access this architecture-specific information with **GetThreadContext** function

thread execution switching is expensive because kernel scheduler is involved

Windows has two mechanisms to reduce this cost:
 - fibers
 - user-mode scheduling (UMS)

Fibers

Fibers allow an app to schedule its own threads of execution rather than rely on the OS priority-based
scheduling mechanism

fibers are often called `lightweight threads`, they are invisible to the kernel because they are implemented
in user mode in kernel32.dll

ConvertThreadToFider function will be called firstly if you want to use fibers

this function will convert the thread to a running fiber, after that, the newly converted fiber can 
create additional fibers via CreateFiber function

BUT using fiber is usually not a good idea, there are some issues in it, I'm not gonna talk about it here

User-mode scheduling threads

UMS threads are only available on 64-bit version of windows

when two or more UMS threads need to perform work in user mode, they can periodically switch execution
contexts (by yielding from one thread to another) in user mode rather than involving the scheduler

from the kernel's perspective, the same kernel thread is still running and nothing has changed

A process and its resources:

![image](https://user-images.githubusercontent.com/48377190/190092691-957fe188-3be8-479c-a1a0-8741809f9910.png)

Jobs

windows provides an extension to the process model called `job`

A job object's main function. is to allow the **management and manipulation of groups of process
as a unit**

in some ways, the job object conpensates for the lack of a structured process tree in Windows

we can view job with ProcExp

![image](https://user-images.githubusercontent.com/48377190/190098762-e843679b-5e64-42e1-ac5f-80c9c7300617.png)

![image](https://user-images.githubusercontent.com/48377190/190098960-7f2628ab-0d4c-4fe5-a4d2-9a787adc11c8.png)

Virtual Memory

**Windows implements a virtual memory system based on a flat (linear) address space that provides each
process with the illusion of having its own large, private address space**

here is an illustration of the relationship between virtual memory and physical memory:

![image](https://user-images.githubusercontent.com/48377190/190100309-bd43a00f-bfc5-45b7-b166-b8fc098a5e11.png)

you see, the contiguous virtual memory space may be not contiguous in physical memory, and some of them
are mapped to disk (paged out)

the chunks in this illustration called pages, and thier default size is 4KB

Kernel mode VS. User mode

to protect user applications from accessing and/or modifying critical OS data, Windows users two processor
access modes: user and kernel mode

Kernel mode refers to a mode of execution in a processor that grants access to all system memory and all CPU instructions

Some processors differentiate between such modes by using the term `code privilege` or `ring level`, while others use terms such as `supervisor mode` and `application mode`

this division will make sure that a misbehaving application can't disrupt the stability of the system as a whole

x86 and x64 architecture define four privilege levels (or rings) to protect system code and data from being overwritten either inadvertently or maliciously by code of lesser privilege

in Windows, kernel mode running at ring 0, and ring 3 for user mode

the reason Windows only uses two levels is that some hardware architectures, such as ARM and MIPS/Alpha, implemented only two privilege levels

for process, each of them has its own private memory space, but for kernel-mode os and device-driver code, only one single virtual address space exists, and they share it

every page in virtual memory is tagged to indicate what access mode the processor must be in to read and/or write this page

pages in system space can be accessed only from kernel mode, whereas all pages in the user address space are accessible from user mode and kernel mode

read-only pages (such as those that contains static data) are not writable from any mode


additionally, on processors that support no-execute memory protection, Windows marks pages containing data as non-executable, thus preventing inadvertent or malicious code execution in data areas ( if Data Execution Prevenntion [DEP] is enabled)

there is no protection in kernel mode, so third-party device driver must be signed to make sure it won't make threats to the stability of OS

**driver-signing mechanism is introduced in Windows 2000, a warning will pop up if an unsigned plug-and-play driver is added, and on x64 ARM Win8.1, the kernel-mode code-signing (KMCS) policy dictates that all device (not only plug-and-play) drivers must be signed with a cryptographic key assigned by one of the major code certifcation authorities**

it's normal for a user thread to spend part of its time executing in user mode and part in kernel mode, because system call will switch it to kernel mode. unless there is no system call called (not likely)

**in fact, because the bulk of the graphics and windosing system also runs in kernel mode, graphics-intensive app spend more of their time in kernel mode than in user mode**

we can use Performance Monitor to verify this: https://youtu.be/Y1L5O3AwRzU

Hypervisor

Hypervisor is onlt a concept, Hyper-V/Vmware/VirtualBox. all of them are hypervisor

due to its highly privileged nature, and because it has access even greater than the kernel itself, a hypervisor has a distinct advantage that goes beyond merely running mutiple guest instances of other operating systems: It can protect and monitor a single host instance to offer assurances and guarantees beyond what the kernel provides

Win10 now leverages the Hyper-V hypervisor to provide a new set of services known as a `virtualization-based security (VBS)`

 - Device Guard
 - Hyper Guard
 - Credential Guard
 - Application Guard
 - Host Guardian and Shielded Fabric

Hyper-V hypervisor makes OS more secure, unlike previous kernel-based security, it won't be affected by malicious signed driver code

Virtual Trust Levels (VTLS), normal operating system and its components are in a less privileged mode (VTL 0), but these VBS technologies run at VTL 1 (a higher privilege), they can not be affected even by kernel mode code

Firmware

UEFI, TPM, these stuff will will make sure the right Windows component is loaded at the very beginning of the boot process

Terminal Services and multiple sessions

Windows client edition support only one session, but for server edition, two simultaneous session, and if appropriately licensed and configured as a terminal server, more than two remote sessions is supported, too

Objects and handles

**The most fundamental difference between an object and an ordianry data structure is that the internal structure of an object is opaque
you must call an object service to get data out of or put data into an object
you can not directly read or change data inside an object
this difference separates the underlying implementation of the object from code that merely use it, a good technique that allows object implementations to be changed easily over time**


not all data structures in the Windows OS are objects, only data that needs to be shared, protected, named, or made visible to user-mode programs (via system service) is placed in objects

structures used by only one component of the OS to implement internal functions are not obejcts

Security

 - Discretionary access control, object's owner will decide who can access this object and who can not, now with Winserver2012 and Win8 come out, this form of discretionary control is improved by implementing attribute-based access control (Dynamic Access Control), a resource's access control list does not necessarily identify individual users and groups. Instead, it identifies required attributes or claims that grant access to a resource, such as "Clearance Level: Top Secret" or "Seniority: 10 Years". With the ability to populate such attributes automatically by parsing SQL databases and schemas through Active Directory, this significantly more elegant and flexible security model helps organizations avoid cumbersome manual group management and group hierarchies
 - Privileged access control, consider this, an employee leaves a company, the administrator needs a way to gain access to files that might have been accessible only to this left employee. In this case, under Windows, the administrator can take ownership of the file so that they can manage its rights as necessary. This is a method of ensuring that someone can get to protected objects if the owner isn't available
 - Mandatory integrity control, tthis is required when an additional level of security control is needed to protect objects that are being accessed from within the same user account, something about UAC, we discuss this later


from Win8, a sandbox called an `AppContainer` is used to host Windows Apps, which provides isolation with relation to other AppContainers and non-Windows Apps processes


Registry

you can't talk much about Windows internals without referring to the registry because it's the system database, a hell of lot of information is stored in it


Unicode 

UNICODE <==> UTF-16LE.  16bit-wide

EXPERIMENT: Viewing exported functions

it's boring, just use [dependecywalker](https://github.com/wqreytuk/article/blob/main/dependencywalker.tar.gz)

Digging into Windows internals

Performance Monitor and Resource Monitor

Kernel debugging

symbols for kernel debugging

**there are four debuggers included in the tools: cdb, btsd, kd and WinDbg, all of them are based on a single debugging engine implemented in DbgEng.dll**

 - cdb and ntsd are user-mode debuggers based on a console user interface
 - kd is a kernel-mode debugger based on a console user interface
 - WinDbg can be used as a user-mode or kernel-mode debugger, but not both at the same time. It provides a GUI for the user
 - The user-mode debuggers (cdb, ntsd, and WinDbg, when used as such) are essentially equivalent. Usage of one or the other is a matter of preference
 - The kernel-mode debuggers (kd and WinDbg, when used as such) are equivalent as well

User-mode debugging

the debugging tools can also be used to attach to a user-mode process and to examine and/or change process memory. There are two options when attaching to a process:
 - Invasive, when you attach to a running process with this option, debugger use the DebugActiveProcess Windows function to establish a connection between the debugger and the debuggee, this permits you to examin and/or change process memory, set breakpoints, and perform other debugging functions, Windows allows you to stop debugging without killing the target process as long as the debugger is detached, not killed
 - Noninvasive, with this option, the debugger simply opens the process with the OpenProcess fucntion, it does not attach to the process as a debugger, this allows you to examine and/or change memory in the target process, but you cannot set breakpoints, this also means it's possible to attach noninvasively even if another debugger is attached invasively

Chapter 2. System architecture

Requirements and design goals

the following **requirements** drove the specification of Windows NT back in 1989:
 - Provide a true 32-bit, [preemptive](https://en.wikipedia.org/wiki/Reentrancy_(computing)), [reentrant](https://en.wikipedia.org/wiki/Reentrancy_(computing)), virtual memory OS
 - Run on multiple hardware architectures and platforms
 - Run and scale well on [symmetric multiprocessing systems](https://zh.wikipedia.org/zh-cn/对称多处理)
 - Be a greate distributed computing platform, both as a network client and as a server
 - Run most existing 16-bit MS-DOS and Microsoft Windows 3.1 applications
 - Meet government requirements for [POSIX](https://en.wikipedia.org/wiki/POSIX) 1003.1 compliance
 - Meet government and industry requirements for OS security
 - Be easily adaptable to the global market by supporting Unicode


To guide the thousands of decisions that had to be made to create a system that met these requirements, the Windows NT design team adopted the following **design goals** at the beginning of the project:
 - Extensibility, the code must be written to comfortably grow and change as market requirements change
 - Portability, the system must be able to run on multiple hardware architectures and must be able to move with relative ease to new ones as market demands dictate
 - Reliability and robustness, the system should protect itself from both internal malfunction and external tampering. Applications should not be able to harm the OS or other applications
 - Compatibility
 - Performance


Windows is not an object-oriented system in the strict sense. Most of the kernel-mode OS code is written in C for portability


Architecture overview

here is an diagramn for a simplified version of Windows architecture, it is very basic, and doesn't show everything

![image](https://user-images.githubusercontent.com/48377190/190408941-c6e51f3d-36fe-4724-9c2a-bf8ea8f94d9c.png)


there are two lines devide the OS to three parts, first line devide OS into User-Mode and Kernel-Mode, the second line devide it into kernel-mode and hypervisor context. Strictly speaking
