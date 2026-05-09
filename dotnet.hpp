#pragma once
#include "def.h"
#include <metahost.h>
#include <corerror.h>
#include <metahost.h>
#include <iostream>
#include <string>
#include <comdef.h>
#include <vector>
#include <fstream>
#include <unknwn.h>
#include "patch.hpp"
#include "overloading.hpp"

DWORD RvaToOffset(PIMAGE_NT_HEADERS ntHeaders, DWORD rva);
LPSTR* convertArgsToLPSTRArray(std::wstring args, int& argsCount);
std::wstring checkCLRVersion(LPCSTR assmblyBytes, size_t assemblyLength, LPCSTR byteSeq, size_t byteSeqLength);
void InitDotnet(std::wstring FilePath, bool isRemote, std::wstring args, bool https, bool powershell);
void Dotnet(std::wstring FilePath, std::wstring args, bool isRemote, bool https, bool powershell);
bool checkFile(std::wstring filePath);