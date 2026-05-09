#include "def.h"
#include "injector.hpp"
#include "dll.hpp"
#include "apc.hpp"
#include <fstream>
#include <vector>
#include <algorithm>
#include <thread>
#pragma once

bool patchRemoteETW(HANDLE hProcess);

void SetupEtwBypass();
LONG WINAPI EtwHwbpHandler(PEXCEPTION_POINTERS exceptions);

bool FullAmsiBypass(bool powershell);
bool FullEtwBypass();
std::vector<BYTE> ReadFileToBuffer(const std::string& filename);
LONG WINAPI UniversalHwbpHandler(PEXCEPTION_POINTERS exceptions);