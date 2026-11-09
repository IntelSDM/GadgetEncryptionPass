# Gadget Encryption Pass
Built for LLVM 19.1 - Windows x64 <br> <br>

Whenever you return a value you emit a MOV RAX xxx RET, this means that your constant is loaded into RAX as it is returned. This means we can call exactly on this gadget to set a known value into RAX. <br>
We make a dangerous assumption though, we assume that common returns are in most windows builds. We check if the MOV RAX IMM is in enough cases then its likely a common return type, therefore it will exist in just about all windows builds. <br>
Since the particular MOV RAX IMM is constantly used, we simply scan it at runtime, populate tables and then use it as a known decryption key.  For gadgets such as ret 1, ret 0. This will never fail. <br>
This provides security against symbolic executors that don't do environment emulation. Combining it with things like your MBA or Opaques, allows you to break Z3/SMT/Simplifiers, as they don't emulate the environment to decrypt the values. <br>


We simply scan the gadget, cache the gadget, then decrypt a constant with it.
<img width="865" height="947" alt="image" src="https://github.com/user-attachments/assets/ffc9a7f9-f6d0-422b-8aa7-8b7fd17311d5" />
<img width="631" height="488" alt="image" src="https://github.com/user-attachments/assets/191323f0-73e6-4cd0-a051-6c2082bd0743" />





## Annotations
```c
__attribute__((annotate("gadgetenc")))
``` 
* Activates The Constant Encryption

## How To Build
* Download [LLVM 19.1](https://github.com/llvm/llvm-project/releases/tag/llvmorg-19.1.0)
* Download [VCPKG](https://github.com/microsoft/vcpkg)
* VCPKG install asmjit
* Open build.bat in a text editor.
* Find the LLVM 19.1 references in the command line, Change them to your file path.
* Find the VCPKG references in the command line, Change them to your file path.
* Run the build script
* Build your application with the ``` -load-pass-plugin ``` Param to the FunctionPass.dll
