#include "debug.hpp"
#include "def.h"

debug antiDebug;

bool debug::rdtscCheck() {
        unsigned long long start = __rdtsc();

        for (volatile int i = 0; i < 10000000; i++);

        unsigned long long end = __rdtsc();

        return (end - start) > 50000000; // adjust experimentally
    }

bool debug::checkPEB() {
        PPEB pPeb = (PPEB)__readgsqword(0x60);

        if (pPeb->BeingDebugged)
            return true;

        // NtGlobalFlag offset (x64)
        DWORD ntGlobalFlag = *(DWORD*)((BYTE*)pPeb + 0xBC);

        if (ntGlobalFlag & 0x70) // heap debugging flags
            return true;

        return false;
    }

bool debug::checkDebug() {

        // PEB checks
        if (checkPEB())
            return true;

        // Timing check
        if (rdtscCheck())
            return true;

        return false;
    }

