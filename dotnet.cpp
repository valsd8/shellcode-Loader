#include "dotnet.hpp"
#pragma comment(lib, "mscoree.lib")


void InitDotnet(std::wstring FilePath, bool isRemote, std::wstring args) {
	if (isRemote) {
		std::cout << "remote dotnet execution is not implemented yet\n";
	}
	else {
		//std::wcout << "Received argument for initialisation: filePath: " << FilePath << " args: " << args << "\n";
		if (checkFile(FilePath)) {
			std::cout << "[+] File is a valid .NET executable, proceeding with execution\n";
			Dotnet(FilePath, args);
		}
		else {
			std::cout << "[-] Could not parse file path or file does not exist, exiting\n";
			return;
		};

	}
};

bool checkFile(std::wstring filePath) {
    HANDLE hFile = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE)
        return false;

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


using namespace mscorlib;

void Dotnet(std::wstring FilePath, std::wstring args)
{
    std::wcout << L"------- Reflective .NET Loader -------\n";

    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (FAILED(hr)) return;

    ICLRMetaHost* metaHost = nullptr;
    ICLRRuntimeInfo* runtimeInfo = nullptr;
    ICorRuntimeHost* runtimeHost = nullptr; // Note: ICor instead of ICLR
    IUnknownPtr pAppDomainUnk = nullptr;
    _AppDomainPtr pDefaultAppDomain = nullptr;
    _AssemblyPtr pAssembly = nullptr;
    _MethodInfoPtr pEntryPoint = nullptr;

    // 1. Read file into memory buffer
    std::ifstream file(FilePath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) { std::cerr << "Failed to open file.\n"; return; }
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<char> buffer(size);
    if (!file.read(buffer.data(), size)) { return; }

    // 2. Setup the Runtime
    hr = CLRCreateInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost, (LPVOID*)&metaHost);
    hr = metaHost->GetRuntime(L"v4.0.30319", IID_ICLRRuntimeInfo, (LPVOID*)&runtimeInfo);

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
    if (FAILED(hr)) { std::cout << "Load_3 failed.\n"; goto cleanup; }

    hr = pAssembly->get_EntryPoint(&pEntryPoint);
    if (FAILED(hr) || pEntryPoint == nullptr) {
        std::cout << "Could not find Entry Point (Main).\n";
        goto cleanup;
    }

    std::cout << "Invoking Entry Point...\n";
    VARIANT varObj; VariantInit(&varObj); varObj.vt = VT_NULL;
    VARIANT varArgs; VariantInit(&varArgs); varArgs.vt = VT_NULL;

    // This executes Main(string[] args)
    hr = pEntryPoint->Invoke_3(varObj, nullptr, &varObj);

cleanup:
    if (psa) SafeArrayDestroy(psa);
    if (runtimeHost) runtimeHost->Release();
    if (runtimeInfo) runtimeInfo->Release();
    if (metaHost) metaHost->Release();
    CoUninitialize();
}