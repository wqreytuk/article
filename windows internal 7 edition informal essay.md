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
