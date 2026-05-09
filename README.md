## Disclaimers ##

do not use for malicious intent only authorized access.
I am not responsable for what u do with it.


A c++ shellcode loader and .net pe loader.
it is using indirect syscalls with module stomping.
it is still in development so stability isnt optimal.
For the shellcode loading u can use module stomping (better tbf) or apc queue injection
For the .net loader part its loading a random dll into memory, overwritting it with the .net pe bytes so it doesnt look like unbacked memory.
To patch amsi and etw this loader is using Hardware breakpoints so ntdll and amsi bytes remains untouched.
Since using LoadLibrary("amsi.dll") in a c++ pe is very suspicious, this loader just hooks ldrLoadDll and getProcAdress and redirect execution to a manually mapped amsi.dll where AmsiScanBuffer is already patched (basic ret).
For etw, the loader hooks ntCreateThreadEx and patch EtwEventWrite in each of these using hwbp so every new threads is patched.



## TO DO ##

Aes key support for encryption
Better code quality
stack spoofing
Ability to remotely load ressource from different protocols instead of just http / https which is currently supported.

## Important ##
in the help menu u will see an option to run powershell script, it doesnt works and is currently still in devellopment

## Usage ##
<img width="1608" height="630" alt="image" src="https://github.com/user-attachments/assets/5bbeeb45-bc5c-43a7-a28f-b17dad01611a" />



