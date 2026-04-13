#pragma once
#include "def.h"
#include <string>

#include "helper.hpp"
#include "syscall.hpp"
#include "syscall_global.hpp"




class injectorMethod {
public:

    BOOL closeH(HANDLE toClose);

    HANDLE process(int process_id);


    NTSTATUS wrMem(HANDLE hProcess, LPVOID rBuffer, PVOID shellcode, SIZE_T len_shellcode);

    NTSTATUS protectMem(HANDLE proc, LPVOID buff);

    NTSTATUS protectMemFlag(HANDLE proc, LPVOID buff, ULONG flag);
    LPVOID vAlloc(HANDLE hProcess, PVOID addr, SIZE_T shellcode_len);
    VOID vFree(HANDLE hProcess, PVOID address);
    HANDLE ntThread(HANDLE proc, LPVOID lpStartAddress, LPVOID lpParameter);

    void waitForSingle(HANDLE addr);

    PVOID findRemoteModule(HANDLE hProcess, const wchar_t* targetDllName);
};

extern injectorMethod mainInjector;