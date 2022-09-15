https://empyreal96.github.io/nt-info-depot/Windows-Internals-PDFs/Windows%20System%20Internals%207e%20Part%201.pdf


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
