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


