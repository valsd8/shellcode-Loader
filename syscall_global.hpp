#pragma once
#include "def.h"

//mySuspendThread
extern "C" PVOID wsysSuspendThread;
extern "C" DWORD ssnsysSuspendThread;


//MyThreadContext
extern "C" PVOID wsysNtGetContextThread;
extern "C" DWORD ssnsysNtGetContextThread;


//myNtSetContextThread
extern "C" PVOID wsysNtSetContextThread;
extern "C" DWORD ssnsysNtSetContextThread;


//myNtResumeThread
extern "C" PVOID wsysNtResumeThread;
extern "C" DWORD ssnsysNtResumeThread;


//myNtOpenThread
extern "C" PVOID wsysNtOpenThread;
extern "C" DWORD ssnsysNtOpenThread;


//vFree
extern "C" PVOID wsysNtFreeVirtualMemory;
extern "C" DWORD ssnsysNtFreeVirtualMemory;


//findThread
extern "C" PVOID wsysNtQuerySystemInformation;
extern "C" DWORD ssnsysNtQuerySystemInformation;

//vAlloc
extern "C" PVOID wsysNtAllocateVirtualMemory;
extern "C" DWORD ssnsysNtAllocateVirtualMemory;


//ntThread
extern "C" PVOID wsysNtCreateThreadEx;
extern "C" DWORD ssnsysNtCreateThreadEx;

//ntWaitForSingleObject
extern "C" PVOID wsysNtWaitForSingleObject;
extern "C" DWORD ssnsysNtWaitForSingleObject;



//NtQueryInformationProcess
extern "C" PVOID wsysNtQueryInfoProcess;
extern "C" DWORD ssnsysNtQueryInfoProcess;



//sysNtReadVirtualMemory

extern  "C" PVOID wsysNtReadVirtualMemory;
extern "C" DWORD ssnsysNtReadVirtualMemory;



//sysNtWriteVirtualMemory
extern "C" PVOID wsysNtProtectVirtualMemory;
extern "C" DWORD ssnsysNtProtectVirtualMemory;


extern "C" PVOID wsysNtWriteVirtualMemory;
extern "C" DWORD ssnsysNtWriteVirtualMemory;


//openProcess

extern "C" PVOID wsysNtOpenProcess;
extern "C" DWORD ssnsysNtOpenProcess;
