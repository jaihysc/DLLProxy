# DLL Proxy

Creates a new DLL which sits between a program and the original DLL. This way you can intercept all DLL calls. *64 bit only*.

```
Game -> Your proxy DLL -> Original DLL
```

Based off DLLProxyGenerator from nitrog0d, modified to allow additional code to be injected into the exported functions easily.

## Build

Open DLLProxyGenerator.sln with Visual Studio and build it.

## Usage

### Generate the proxy DLL source

```bash
DLLProxy.exe "path/to/your/dll"
```

### Build the proxy DLL

Create a new Visual Studio C++ DLL project. Copy the generated proxy files into your project.
Remove every other file like stdafx.h, pch.h, framework.h, dllmain.cpp.
Change the following settings:

* C/C++ -> Precompiled Headers -> Precompiled Header = Not Using Precompiled Headers
* Linker -> Input > Module Definition File = dllname.def (the .def file you copied to the project folder)
* A .asm file was created alongside the .cpp and .def files. Before you add this to the project, you should right click the project -> Build Dependencies -> Build Customizations and then check ".masm". This will allow the .asm file to work correctly.
* Now add the .asm file to the project as well. I'm not sure if the correct settings are set automatically, so to double check, right click it and go to properties. And under "General -> Item Type", make sure it's set to: Microsoft Macro Assembler.

### Use the new DLL

Rename the orignal dll to have suffix `_original`, e.g., `mydll_original.dll`. Copy your new proxy inside the program directory.

If your program crashes, ensure that your have the dependent dlls installed by looking at the new proxy dll's imports (e.g., vcruntime140_1.dll).

By default, it outputs all function calls and their arguments to `<name>.log`

