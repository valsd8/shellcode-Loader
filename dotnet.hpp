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




void InitDotnet(std::wstring FilePath, bool isRemote, std::wstring args);
void Dotnet(std::wstring FilePath, std::wstring args);
bool checkFile(std::wstring filePath);