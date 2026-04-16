#include "def.h"
#include "injector.hpp"
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
void ApplyHwBpToThread(DWORD tid);