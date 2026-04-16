#include "def.h"
#include "injector.hpp"
#include "dll.hpp"
#include <fstream>
#include <vector>
#include <algorithm>
#include <thread>
#pragma once


bool patchRemoteETW(HANDLE hProcess);
bool patchRemoteAmsi(HANDLE hProcess);

void SetupEtwBypass();
LONG WINAPI EtwHwbpHandler(PEXCEPTION_POINTERS exceptions);
void SetupAMSIBypass();
LONG WINAPI AmsiHwbpHandler(PEXCEPTION_POINTERS exceptions);
void MonitorThreads();
bool FullAmsiBypass();
void ApplyHwBpToThread(DWORD tid);
LONG WINAPI UniversalHwbpHandler(PEXCEPTION_POINTERS exceptions);