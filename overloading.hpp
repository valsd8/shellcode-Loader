#include "def.h"


PVOID GetStompedAddress(HANDLE targetProcess, char* shellcode, size_t shellcodeSize);

using myNtCreateSection = NTSTATUS(NTAPI*)(PHANDLE, ULONG, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
using myNtMapViewOfSection = NTSTATUS(NTAPI*)(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG);