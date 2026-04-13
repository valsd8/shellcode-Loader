#include "syscall_global.hpp"
//mySuspendThread

PVOID wsysSuspendThread = nullptr;
DWORD ssnsysSuspendThread = 0;

//MyThreadContext

PVOID wsysNtGetContextThread = nullptr;
DWORD ssnsysNtGetContextThread = 0;

//myNtSetContextThread

PVOID wsysNtSetContextThread = nullptr;
DWORD ssnsysNtSetContextThread = 0;

//myNtResumeThread

PVOID wsysNtResumeThread = nullptr;
DWORD ssnsysNtResumeThread = 0;

//myNtOpenThread

PVOID wsysNtOpenThread = nullptr;
DWORD ssnsysNtOpenThread = 0;

//vFree

PVOID wsysNtFreeVirtualMemory = nullptr;
DWORD ssnsysNtFreeVirtualMemory = 0;

//findThread

PVOID wsysNtQuerySystemInformation = nullptr;
DWORD ssnsysNtQuerySystemInformation = 0;

//vAlloc


PVOID wsysNtAllocateVirtualMemory = nullptr;
DWORD ssnsysNtAllocateVirtualMemory = 0;

//ntThread


PVOID wsysNtCreateThreadEx = nullptr;
DWORD ssnsysNtCreateThreadEx = 0;

//ntWaitForSingleObject


PVOID wsysNtWaitForSingleObject = nullptr;
DWORD ssnsysNtWaitForSingleObject = 0;




//NtQueryInformationProcess


PVOID wsysNtQueryInfoProcess = nullptr;
DWORD ssnsysNtQueryInfoProcess = 0;



PVOID wsysNtReadVirtualMemory = nullptr;
DWORD ssnsysNtReadVirtualMemory = 0;


//sysNtWriteVirtualMemory

PVOID wsysNtProtectVirtualMemory = nullptr;
DWORD ssnsysNtProtectVirtualMemory = 0;


PVOID wsysNtWriteVirtualMemory = nullptr;
DWORD ssnsysNtWriteVirtualMemory = 0;



//openProcess


PVOID wsysNtOpenProcess = nullptr;
DWORD ssnsysNtOpenProcess = 0;

