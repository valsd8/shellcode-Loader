#pragma once
#include "def.h"
#include <metahost.h>
#include <corerror.h>



void InitDotnet(std::wstring FilePath, bool isRemote, std::wstring args);
void Dotnet(std::wstring FilePath, std::wstring args);
bool checkFile(std::wstring filePath);