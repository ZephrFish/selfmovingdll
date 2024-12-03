# selfmovingdll
this is a DLL sleep obfuscation proof of concept
where instead of changing the region of the DLL between RW/RWX
it frees itself and allocates a new memory region for itself, all in sequence during ROP

why?:
RWX memory does not immediately mean it is suspicious, due to legit use of it by things like JIT just in time compilation
however, repeatedly changing it between RW/RWX is a whole lot more suspicious, since it is not usual behavior for JIT, and is pretty typical for sleep obfuscated payloads

extra info about this project:
- instead of using waitable timers and other stuff, this project uses just a pure rop chain
- automatically fixes all corrupted return addresses in the stack
- encrypts using KsecDD kernel driver

note:
- may run into crashes if CRT is used, due to CRT holding function pointers back to it's own code
- since this is only a proof of concept:
  - I did not do much with the DLL initialization process, just used a CreateThread
  - I did not implement stack spoofing, so there can still be detections regarding of that
    make sure to change these stuff to fit your use

inspirations:
https://sillywa.re/posts/flower-da-flowin-shc/
