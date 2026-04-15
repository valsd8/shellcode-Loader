#include "def.h"
#include "injector.hpp"
#pragma once


bool patchRemoteETW(HANDLE hProcess);
bool patchRemoteAmsi(HANDLE hProcess);

void SetupEtwBypass();
LONG WINAPI EtwHwbpHandler(PEXCEPTION_POINTERS exceptions);
void SetupAMSIBypass();
LONG WINAPI AmsiHwbpHandler(PEXCEPTION_POINTERS exceptions);