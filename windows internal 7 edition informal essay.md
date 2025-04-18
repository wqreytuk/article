[original book pdf version -- part I](https://github.com/wqreytuk/article/blob/main/Windows%20System%20Internals%207e%20Part%201(1).pdf)

[original book pdf version -- part II](https://github.com/wqreytuk/article/blob/main/Windows%20Internals%20Part%202%207Ed.pdf)

[Sysinternals Suite](https://github.com/wqreytuk/article/blob/main/sysinternalsuite.tar.gz)

[Slpolicy.exe](https://github.com/wqreytuk/article/tree/main/SlPolicy)

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

![image](https://img-blog.csdnimg.cn/548d13f7a6b94964b98e483d94f8c3e7.png)

there are two major components:

 - CLR -- Common Language Runtime, this is the run-time engine for .NET and a Just In Time -- JIT compiler is included
   in, this compiler will translate Common Intermediate Language -- CIL instructions to the underlying hardware CPU
   machine language, and a grabage collector is included, too
   CLR is implemented as a COM in-process server (DLL) and it uses various facilities provided by the Windows API

 - FCL -- .NET Framework Class Library, this is a large collection of types that implement functionality typically nedded
   by client and server applications, such as user interface services, networking, database access and much more

   

here is an illustration for the relationship between the .NET framework and the OS:

![image](https://img-blog.csdnimg.cn/14370faac6964a54a7b38a1ae4ac5321.png)

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

![image](https://img-blog.csdnimg.cn/81c380ca43ae451eb0039e4ac0e44858.png)

![image](https://img-blog.csdnimg.cn/c85ec798465d4c1aa18e434fdd46681b.png)

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

![image](https://img-blog.csdnimg.cn/1c1ffc0f66844f9db6f4d8d441780ddd.png)

Jobs

windows provides an extension to the process model called `job`

A job object's main function. is to allow the **management and manipulation of groups of process
as a unit**

in some ways, the job object conpensates for the lack of a structured process tree in Windows

we can view job with ProcExp

![image](https://img-blog.csdnimg.cn/b0ed56db70924d6f83e01c7145acdebe.png)

![image](https://img-blog.csdnimg.cn/0f2383cbc08c4843ae14603e5d89bc23.png)

Virtual Memory

**Windows implements a virtual memory system based on a flat (linear) address space that provides each
process with the illusion of having its own large, private address space**

here is an illustration of the relationship between virtual memory and physical memory:

![image](https://img-blog.csdnimg.cn/57b37411d238414e99f7ae5f9d2798ef.png)

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

![image](https://img-blog.csdnimg.cn/4f1aa6bda3db43c4b7fa86c38d6b437d.png)


there are two lines divide the OS to three parts, first line divide OS into User-Mode and Kernel-Mode, the second line divide it into kernel-mode and hypervisor context. Strictly speaking, the hypervisor still runs with the same CPU privilege level (0) as the kernel, but because it uses specialized CPU instructions (VT-x on Intel, SVM on AMD), it can both isolate itself from the kernel while also monitoring it (and applications). For these reasons, you may often hear the term `ring -1` thrown around (which is inaccurate)

there are four basic types of user-mode processes:

 - User Processes
 - Service process
 - System processes
 - environment subsystem server processes

in the diagram above, Subsystem DLLs box is below the Service Processes and User Processes boxes. Under Windows, user applications don't call the native Windows OS service directly. Rather, they go through one or more `subsystem dynamic-link libraries (DLLs)`. The role of subsystem DLLs is to translate a documented function into the appropriate internal (and generally undocumented) native system service calls implemented mostly in Ntdll.dll. This translation might or might not involve sending a message to the environment subsystem process that is serving the user process.



The kernel-mode components of Windows include the following:

- **Executive**, the Windows executive contains the base OS services, such as memory management, process and thread management, security, I/O, networking, and inter-process communication
- **The Windows kernel**, this consists of low-level OS functions, such as thread scheduling, interrupt and exception dispatching, and multiprocessor synchronization. It also provides a set of routines and basic objects that the rest of the executive uses to implement higher-level constructs
- **Device drivers**, this includes both hardware device drivers, which translate user I/O function calls into specific hardware device I/O requests, and non-hardware device drivers, such as file system and network drivers
- **The Hardware Abstraction Layer (HAL)**, this is a layer of code that isolates the kernel, the device drivers, and the rest of the Windows executive fro platform-specific hardware differences (such as differences between motherboards)
- **The windowing and graphics system**, this implements the graphical user interface (GUI) functions (better known as the Windows USER and GDI functions), such as dealing with windows, user interface controls, and drawing
- **The hypervisor layer**, this is composed of a single component: the hypervisor itself. There are no drivers or other modules in this environment. That being said, the hypervisor is itself composed of multiple internal layers and services, such as its own memory manager, virtual processor scheduler, interrupt and timer management, synchronization routines, partitions (virtual machine instances) management and inter-partition communication (IPC), and more



here is the file names of the core Windows OS components

| File  Name                                         | Components                                                   |
| -------------------------------------------------- | ------------------------------------------------------------ |
| Ntoskrnl,exe                                       | Executive and kernel                                         |
| hal.dll                                            | HAL                                                          |
| Win32k.sys                                         | Kernel mode part of the Windows subsystem (GUI)              |
| Hvix64.exe (Intel), Hvax64.exe (AMD)               | Hypervisor                                                   |
| .sys files in  %SystemRoot%\System32\Drivers       | Core drivers files, such as Direct X, Volume Management TCP/IP, TPM and  ACPI support |
| Ntdll.dll                                          | Internal support functions and system service dispatch stubs to executive  functions |
| Kernel32.dll, Advapi32.dll, User32.dll,  Gdi32.dll | Core Windows subsystem DLLs                                  |



before we dig into details of these system components, though, let's examine some basics about the Windows kernel design, starting with how Windows achieves portability across multiple hardware architectures



Portability

Windows achieves portability across hardware architectures and platforms in two primary ways:

- **By using a layered design**, low-level portions of the system that are processor-architecture-specific or platform-specific isolated into separate modules so that upper layers of the system can be shielded from the differences between architectures and among hardware platforms. The two key components that provide OS portability are the kernel (contained in Ntoskrnl.exe) and the HAL (contained in HAL.dll)
- **By using C**

Symmetric multiprocessing



`Multitasking` is the OS technique for sharing a single processor among multiple threads of execution

as there is a Symmetric multiprocessing, there is a `asymmetric multiprocessing` (ASMP), in which the OS typically selects one processor to execute OS kernel code while other processors run only user code. Here is their difference illustration:

![image-20220916103637992](https://img-blog.csdnimg.cn/e2814d26f9994908861abf57c2def7b7.png)  



SMT -- simultaneous multi-thread was first introduced to Windows system by adding support for Intel's Hyper-Threading Technology, which provides two logical processors for each physical core. Each logical processor has its own CPU state, but the execution engine and onboard cache are shared. This permits one logical CPU to make progress while the other logical CPU is stalled (such as after a cache miss or branch misprediction). Confusingly, the marketing literature for both companies (Intel and AMD) refers to these additional cores as `threads`, so you'll often see claims such as "four cores, eight threads". This indicates that up to eight threads can be scheduled, hence, the existence of eight logical processors



NUMA -- non-uniform memory access, processors are grouped in smaller units called `nodes`. Each node has its own processors and memory and is connected to the larger system through a cache-coherent interconnect bus

The idea of NUMA is that node-local memory is faster to reference than memory attached to other nodes. The system attempts to improve performance by scheduling threads on processors that are in the same node as the memory being used. It attempts to satisfy memory-allocation requests from within the node, but it will allocate memory from other nodes if necessary

ARM version of Windows also support a technology known as `heterogeneous multi-processing` whose implementation on such processors is called `big.LITTLE`. This type of SMP-based design differs from traditional ones in that not all processor cores are identical in their capabilities, yet unlike pure heterogeneous multi-processing, they are still able to execute the same instructions. The differences, then, comes from the clock speed and respective full load/idle power draws, allowing for a collection of slower cores to be paired with faster ones.



Think of sending an e-mail on an older dual-core 1 GHz system connected to a modern Internet connection. It's unlikely this will be any slower than on an eight-core 3.6 GHz machine because bottlenecks are mostly caused by human input typing speed and network bandwidth, not raw processing power. Yet even in its deepest power-saving mode, such a modern system is likely to use significantly more power than the legacy system. Even if it could regulate itself down to 1GHz, the legacy system has probably set itself to 200 MHz, for example

By being able to pair such legacy mobile processors with top-of-the-line ones, ARM-based platforms paired with a compatible OS kernel scheduler can maximize processing power when needed (by turning on all cores), strike a balance (by having certain big cores online and other little ones for other tasks), or run in extremely low power modes (by having only a single little core online -- enough for SMS and push e-mail). By supporting what are called `heterogeneous scheduling policies`, Windows 10 allows threads to pick and choose between a policy that satisfies their need, and will interact with the scheduler and power manager to best support it.

So ARM-based system will save more power

EXPERIMENT: Determining features enabled by licensing policy



As mentioned, Windows supports more than 100 different features that can be enabled through the software licensing mechanism



Policy settings are organized by a `facility`, which represents the owner module for which the policy applies. You can display a list of all facilities known to the tool by running SlPolicy.exe with the -f switch:

![image-20220916134418160](https://img-blog.csdnimg.cn/a761222f3e7946b89618e2edab7917df.png)

you can then add the name of any facility after the switch to display the policy for that facility. For example, to look at the limitations on CPUs and available memory, user the Kernel facility:

Windows 10 Education

![image-20220916134713113](https://img-blog.csdnimg.cn/66255e6b531e4b28a356c0373bb905e2.png)

and here is what I got in server 2012 R2 Datacenter:

![image-20220916140946948](https://img-blog.csdnimg.cn/0a9631892cc7457bbe26f7f44c88250e.png)

you can see the deference of the value between them are huge

Checked build

for device driver developers

EXPERIMENT: Determining if you are running the checked build version Windows



just run this command in powershell:

```powershell
Get-WmiObject win32_operatingsystem | select debug
```

`False` means your OS is not running the checked build

Virtualization-based security atchitecture overview

if an unwanted piece of kernel-mode code makes it into the system (because of some yet-unpatched kernel or driver vulnerability or because the user was tricked into installing a malicious or vulnerable driver), the system is essentially compromised because all kernel-mode code has complete access to the entire system

here is an illustration for Windows10 and Server2016:

![image](https://user-images.githubusercontent.com/48377190/190905827-c037d08a-76ed-4aa6-83ae-721b71374c26.png)

with VBS enabled, a VTL1 is presented, which contains its own secure kernel running in the privileged processor mode (that is, ring 0 on x86/x64). Similarly, a run-time user environment mode, called the Isolated User Mode (IUM), now exists, which runs in unprivileged mode (that is, ring 3)

In this architecture, the secure kernel is its own separate binary, which is found under the name securekernel.exe 



![image-20220919084544737](https://img-blog.csdnimg.cn/031919bd233c4c158e92910050f17cac.png)

As for IUM, it's both an environment that restricts the allowed system calls that regular user-mode DLLs can make (thus limiting which of these DLLs can be loaded) and a framework that adds special secure system calls that can execute only under VTL1



These additional system calls are exposed in a similar way as regular system calls: through an internal system library named `iumdll.dll` (the VTL1 version of `ntdll.dll`) and a Windows subsystem-facing library named `iumbase.dll` (the VTL1 version of `kernelbase.dll`)

secure kernel is known as `proxy kernel`, because it forwards system calls to VLT0 kernel, it does not implement a full range of system capabilities. For VTL 1 user-mode applications, any kind of I/O, including file, network, and registry-base, is complete prohibited. And not a single driver is allowed to be communicated with



The secure kernel however, by both running at VTL 1 an being in kernel mode, does have complete access to VTL 0 memory and resources. It can use the hypervisor to limit the VTL 0 OS access to certain memory locations by leveraging CPU hardware support known as Second Level Address Translation (SLAT). SLAT is the basis of Credential Guard technology, which can store secrets in such locations. Similarly, the secure kernel can use SLAT technology to interdict and control execution of memory location, a key covenant of Device Guard

Because the hypervisor is the first system conponent to be launched by the boot loader, it can program the SLAT and I/O MMU as it sees fit, defining the VTL 0 and 1 execution environments. Then, while in VTL 1, the boot loader runs again, loading the secure kernel, which can configure the system further to its needs. Only then is the VTL dropped, which will see the execution of the normal kernel, now living in its VTL 0 jail, unable to escape



Key system components



![image-20220919094121048](https://img-blog.csdnimg.cn/676b2ec11756465298f689eddefdef22.png)

Environment subsystems and subsystem DLLs



the role of an environment subsystem is to expose some subset of the base Windows executive system services to application programs.



each executable image (.exe) is bound to one and only one subsystem. When an image is run, the process creation code examines the subsystem type code in the image header so that it can notify the proper subsystem of the new process. This type code is specified with the /SUBSYSTEM linker option of the Microsoft Visual Studio linker (or through the SubSystem entry in the Linker/System property page in the project's properties)



As mentioned, user applications don't call Windows system services directly. Instead, they go through one or more subsystem DLLs. These libraries export the documented interface that the programs linked to that subsystem can call. For example, the Windows subsystem DLLs (such as kernel32.dll, advapi32.dll, user32.dll, and gdi32.dll) implement the Windows API functions. The SUA subsystem DLL (psxdll.dll) is used to implement the SUA API functions (on Windows version that supported POSIX)



EXPERIMENT: Viewing the image subsystem type

When an application calls a function in a subsystem DLL, one of three things can occur:

- The function is entirely implemented in user mode inside the subsystem DLL
- The function requires one or more calls to the Windows executive
- The function requires some work to be done in the environment subsystem process

subsystem startup



subsystems are started by the Session Manager (Smss.exe) process. The subsystem startup information is stored under the registry key:

```
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\SubSystems
```

![image-20220919115151053](https://img-blog.csdnimg.cn/a847406df79841d1a9fd6eaadf71402f.png)



The Required value lists the subsystems that load when the system boots: Debug and Windows



from a practical perspective, having each subsystem implement all the code to handle windowing and display I/O would result in a large amount of duplication of system functions that, ultimately, would negatively affect both system size and performance



the Windows designer decided to locate there basic function to Windows subsystem and have all the other subsystems call on the Windows subsystem to perform display I/O.



As a result of this design decision, the Windows subsystem is a required component for any Windows system, even on server systems with no interactive users logged in. Because of this, the process is marked as a critical process (which means if it exits for any reason, the system crashes)

The Windows subsystem consists of the following major components:

- for each session, an instance of the environment subsystem process (csrss.exe) loads four DLLs (basesrv.dll, winsrv.dll, sxssrv.dll, and csrsrv.dll) that contain support for the following:
  - Various housekeeping tasks related to creating and deleting processes and threads
  - Shutting down Windows applications (through the ExitWindowsEx API)
  - Containing .ini file to registry location mappings for backward compatibility
  - Sending certain kernel notification messages (such as those from the Plug-and-Play manager) to Windows applications as Windows message (WM_DEVICECHANGE)
  - Portions of the support for 16-bit virtual DOS machine (VDM) processes (32-bit Windows only)
  - Side-by-Side (SxS)/Fusion and manifest cache support
  - Several natural language support functions, to provide caching
- A kernel-mode device driver (win32k.sys) that contains the following:
  - windows manager
  - Graphic Device Interface (GDI), which is a library of functions for graphics output devices and includes functions for line, text, and figure drawing and for graphics manipulation
  - Wrappers for DirectX support that is implemented in another kernel driver （dxgkrnl.sys)
- The console host process (conhost.exe), which provides support for console (character cell) applications
- The Desktop Window Manager (dwm.exe), which allows for compositing visible window rendering into a single surface through the CDD and DirectX
- Subsystem DLLs (such as kernel32.dll, advapi32.dll, user32.dll, and gdi32.dll) that translate documented Windows API functions into the appropriate and undocumented (for user-mode) kernel-mode system service calls in ntoskrnl.exe and win32k.sys
- Graphic device drivers for hardware-dependent graphics display drivers, printer drivers, and video miniport drivers





windows 10 and win32k.sys



console window host



​	in the original Windows subsystem design, the subsystem process (csrss.exe) was responsible for managing console windows and each console application (such as cmd.exe, the command prompt) communicated with csrss.exe. Starting with Windows 7, a separate process is used for each console window on the system: the console window host (conhost.exe). (A single console window can be shared by multiple console applications, such as when you launch a command prompt from the command prompt. By default the second command prompt shares the console window of the first)

![image-20220919160035908](https://img-blog.csdnimg.cn/0f6b8b4cc8fe4d0bb374532409953e0c.png)



but if you execute `start cmd` in current command prompt, a new conhost.exe process will be created



![image-20220919160206999](https://img-blog.csdnimg.cn/1c8a4ab4e63c4229ad05091dc73e0d50.png)

there is a little bit difference between Win7 and Win8 or later. In Win7, the conhost.exe is is spawned from the csrss.exe, but in Win8 or later, conhost.exe is spawned from cmd.exe:

Win7:

![image-20220919161103970](https://img-blog.csdnimg.cn/111e987be171498ab06268c649a0aeea.png)

Win8 or later:

![image-20220919161141913](https://img-blog.csdnimg.cn/a99968b5cad341da8a81b1e3853f24a4.png)

the following process expolrer screen shows the handle conhost.exe holds open to the device object exposed by condrv.sys named `\Device\ConDrv`

![image-20220919162246914](https://img-blog.csdnimg.cn/729b18c6c88f4ee6b3215df49d3334e1.png)

The real workhorse of conhost.exe is a DLL it loads (`\Windows\System32\conhostV2.dll`) that includes the bulk of code that communicates with the console driver

Other subsystems

ntdll.dll



ntdll.dll is special system support library primarily for the use of subsystem DLLs and antive applications. (Native in this context refers to images that are not tied to any particular subsystem.) It contains two types of functions:

- System service dispatch stubs to Windows executive system services
- Internal support functions used by subsystems, subsystem DLLs, and other native images



the first group of functions provides the interface to the Windows executive system services that can be called from user mode. There are more than 450 such functions, such as NtCreateFile, NtSetEvent, and so on. As noted, most of the capabilities of these functions are accessible through the Windows API. (A number are not, however, and are for use only by specific OS-internal components)

For each of these functions, ntdll.dll contains an entry point with the same name. The code inside the function contains the architecture-specific instruction that causes a transition into kernel mode to invoke the system service dispatcher. (This is explained in more detail later) After verifying some parametrs, this system service dispatcher calls the actual kernel-mode system service that contains the real code inside ntoskrnl.exe. The following experiment shows what these functions look like.



EXPERIMENT: Viewing the system service dispatcher code





Native images



some images (executables) don't belong to any subsystem. In other words, they don't link against a set of subsystem DLLs, such as kernel32.dll  for the Windows subsystem. Instead, they link only to ntdll.dlll, which is the lowest common denominator that spans subsystems

smss.exe (Session Manager) is the first user-mode process to be created, directly by the kernel

so it cannot be dependent on the Windows subsystem because csrss.exe (the Windows subsystem process) has not started yet.



In fact, smss.exe is responsible for launching csrss.exe. Another example is the Autochk utility that sometimes runs at system startup to check disks. Because it runs relatively early in the boot process (launched by smss.exe, in fact), it cannot depend on any subsystem.



Here is the import table for smss.exe, only a ntdll.dll:

![image-20220920142954776](https://img-blog.csdnimg.cn/6f26c51e35074d57a3db7d160aaa2c6e.png)

and the subsystem field is `driver`, in the book, it is `native`, according to the official doc, they are actually the same thing

![image-20220920143131748](https://img-blog.csdnimg.cn/62db50ddd41047659ec61ba129a94ca0.png)



Executive

The Windows executive is the upper layer of ntoskrnl.exe. (The kernel is the lower layer.) The executive includes the following types of functions:

- **Functions that are exported and callable from user mode**, these functions are called `system services` and are exported via ntdll.dll (such as NtCreateFile from the previous experiment). Most of the services are accessible through the Windows API or the APIs of another environment subsystem. A few services, however, aren't available through any documented subsystem function. (Examples include ALPC and various query functions such as NtQueryInformationProcess, specialized functions such as NtCreatePagingFile, and so on.)
- **Device driver functions that are called through the DeviceIoControl function**, this provides a general interface from user mode to kernel mode to call functions in device drivers that are not associated with a read or write. The driver used fro Process Explorer and Process Monitor from Sysinternals are good examples of that as is the console driver (condrv.sys) mentioned earlier
- **Functions that can be called only from kernel mode that are exported and documented in the WDK**, these include various support routines, such as the I/O manager (start with Io), general executive functions (Ex) and more, needed for device driver developers
- **Functions that are exported and can be called from kernel mode but are not documented in the WDK**, these include the function called by the boot video driver, which start with Inbv
- **Functions that are defined as global symbols but are not exported**, these include internal support functions called within ntoskrnl.dll, such as those that start with Iop (internal I/O manager support functions) or Mi (internal memory management support functions).
- **Functions that are internal to a module that are not defined as global symbols**. these functions are used exclusively by the executive and kernel

Kernel

The kernel consists of a set of functions in ntoskrnl.exe that provides fundamental mechanisms.


Creating a process

The Windows API provides serveral functions for creating processes. The simplest is CreateProcess, which attempts to create a process with the same access token as the creating process.



If a different token is required, CreateProcessAsUser can be usedm which accepts an extra argument (the first) -- a handle to a token object that was already somehow obtained (for example, by calling the LogonUser function).



Examing the CSR_PROCESS



csrss processes are protected (see later in this chapter for more on protected processes), so it's not possible to attach a user mode debugger to a csrss process (not even with elevated privileges or non-invasive). Instead, we'll use the kernel debugger 





