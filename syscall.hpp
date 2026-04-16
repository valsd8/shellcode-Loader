#pragma once
#include "def.h"
#include <string>

#include "helper.hpp"

#define UP -32
#define DOWN 32 


class syscallHandling {
public:
    struct SYSCALL_DATA {
        DWORD ssn;
        PVOID syscallAddress;
    };
    PVOID getFunctionAddressByHash(const wchar_t* library, DWORD targetHash);

    SYSCALL_DATA getSyscallDataByHash(const wchar_t* library, DWORD targetHash);

    SYSCALL_DATA getSyscallDataFromEncoded(unsigned char* encodedDll, DWORD hash);
    PVOID getFunctionAddressByHashWithModule(HMODULE libraryBase, DWORD targetHash);


};
extern syscallHandling syscallHandler;