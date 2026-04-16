#include "def.h"
#include "injector.hpp"
#pragma once

HMODULE LocalManualMap(BYTE* pSrcData);
void RebaseDllRemote(BYTE* pLocalBuffer, IMAGE_NT_HEADERS* pNtHeader, uintptr_t remoteTargetBase);
void RebaseDll(BYTE* pBase, IMAGE_NT_HEADERS* pNtHeader);
bool ResolveImports(BYTE* pBase, IMAGE_NT_HEADERS* pNtHeader);

using f_LoadLibraryA = HINSTANCE(WINAPI*)(const char* lpLibFilename);
using f_GetProcAddress = FARPROC(WINAPI*)(HMODULE hModule, LPCSTR lpProcName);
using f_DLL_ENTRY_POINT = BOOL(WINAPI*)(void* hDll, DWORD dwReason, void* pReserved);





#ifdef _WIN64
using f_RtlAddFunctionTable = BOOL(WINAPIV*)(PRUNTIME_FUNCTION FunctionTable, DWORD EntryCount, DWORD64 BaseAddress);
#endif