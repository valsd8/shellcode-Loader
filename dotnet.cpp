#include "dotnet.hpp"
#include <metahost.h>
#include <iostream>
#include <string>
#include <comdef.h>
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

void Dotnet(std::wstring FilePath, std::wstring args)
{
    std::wcout << L"------- In Dotnet function -------\n";
    std::wcout << L"Target: " << FilePath << L"\n";

    HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    if (FAILED(hr)) return;

    // Utilisation de Smart Pointers (CComPtr) recommandée en production, 
    // mais restons sur des pointeurs bruts pour la clarté :
    ICLRMetaHost* metaHost = nullptr;
    ICLRRuntimeInfo* runtimeInfo = nullptr;
    ICLRRuntimeHost* runtimeHost = nullptr;
    DWORD pReturnValue = 0;

    // Aide pour afficher les erreurs HRESULT proprement
    auto LogError = [](const char* msg, HRESULT hr) {
        _com_error err(hr);
        std::cout << msg << " Error: " << std::hex << hr << " (" << err.ErrorMessage() << ")\n";
        };

    hr = CLRCreateInstance(CLSID_CLRMetaHost, IID_ICLRMetaHost, (LPVOID*)&metaHost);
    if (FAILED(hr)) { LogError("MetaHost creation failed", hr); goto cleanup; }

    hr = metaHost->GetRuntime(L"v4.0.30319", IID_ICLRRuntimeInfo, (LPVOID*)&runtimeInfo);
    if (FAILED(hr)) { LogError("GetRuntime failed", hr); goto cleanup; }

    hr = runtimeInfo->GetInterface(CLSID_CLRRuntimeHost, IID_ICLRRuntimeHost, (LPVOID*)&runtimeHost);
    if (FAILED(hr)) { LogError("GetInterface failed", hr); goto cleanup; }

    hr = runtimeHost->Start();
    if (FAILED(hr)) { LogError("RuntimeHost Start failed", hr); goto cleanup; }

    // Tentative d'exécution
    hr = runtimeHost->ExecuteInDefaultAppDomain(
        FilePath.c_str(),
        L"main.Program", // Vérifiez bien le Namespace.Classe
        L"message",         // Nom de la méthode
        args.c_str(),    // L'argument passé au Main(string arg)
        &pReturnValue
    );

    if (SUCCEEDED(hr)) {
        std::cout << "Success! Managed code returned: " << pReturnValue << "\n";
    }
    else {
        LogError("Execution failed", hr);
        // Si l'erreur est 0x80131513, c'est que la méthode C# n'est pas trouvée ou mal signée.
    }

cleanup:
    if (runtimeHost) runtimeHost->Release();
    if (runtimeInfo) runtimeInfo->Release();
    if (metaHost) metaHost->Release();
    CoUninitialize();
}