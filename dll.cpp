#include <windows.h>
#include "dll.hpp"
#include <iostream>

// Helper to fix the Base Relocation Table
void RebaseDll(BYTE* pBase, IMAGE_NT_HEADERS* pNtHeader) {
    auto& relocationDir = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    if (relocationDir.Size == 0) return;

    auto* pRelocBlock = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pBase + relocationDir.VirtualAddress);
    uintptr_t delta = reinterpret_cast<uintptr_t>(pBase) - pNtHeader->OptionalHeader.ImageBase;

    while (pRelocBlock->VirtualAddress != 0) {
        DWORD entryCount = (pRelocBlock->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
        WORD* pRelativeInfo = reinterpret_cast<WORD*>(pRelocBlock + 1);

        for (DWORD i = 0; i < entryCount; ++i) {
            if ((pRelativeInfo[i] >> 12) == IMAGE_REL_BASED_DIR64 || (pRelativeInfo[i] >> 12) == IMAGE_REL_BASED_HIGHLOW) {
                uintptr_t* pPatch = reinterpret_cast<uintptr_t*>(pBase + pRelocBlock->VirtualAddress + (pRelativeInfo[i] & 0xFFF));
                *pPatch += delta;
            }
        }
        pRelocBlock = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocBlock) + pRelocBlock->SizeOfBlock);
    }
}

// Helper to resolve the Import Address Table (IAT)
bool ResolveImports(BYTE* pBase, IMAGE_NT_HEADERS* pNtHeader) {
    auto& importDir = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir.Size == 0) return true;

    auto* pImportDesc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pBase + importDir.VirtualAddress);

    while (pImportDesc->Name != 0) {
        char* szModName = reinterpret_cast<char*>(pBase + pImportDesc->Name);
        HMODULE hMod = GetModuleHandleA(szModName);
        if (!hMod) hMod = LoadLibraryA(szModName);

        if (!hMod) return false;

        auto* pThunk = reinterpret_cast<IMAGE_THUNK_DATA*>(pBase + pImportDesc->FirstThunk);
        auto* pOrigThunk = reinterpret_cast<IMAGE_THUNK_DATA*>(pBase + pImportDesc->OriginalFirstThunk);

        for (; pThunk->u1.AddressOfData != 0; ++pThunk, ++pOrigThunk) {
            if (IMAGE_SNAP_BY_ORDINAL(pOrigThunk->u1.Ordinal)) {
                pThunk->u1.Function = (uintptr_t)GetProcAddress(hMod, (char*)(pOrigThunk->u1.Ordinal & 0xFFFF));
            }
            else {
                auto* pImportData = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + pOrigThunk->u1.AddressOfData);
                pThunk->u1.Function = (uintptr_t)GetProcAddress(hMod, pImportData->Name);
            }
            if (!pThunk->u1.Function) return false;
        }
        pImportDesc++;
    }
    return true;
}

// The Main Mapper Function
HMODULE LocalManualMap(BYTE* pSrcData) {
    auto* pDosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(pSrcData);
    if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;

    auto* pNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(pSrcData + pDosHeader->e_lfanew);
    auto* pOptHeader = &pNtHeader->OptionalHeader;

    // Allocate memory
    BYTE* pTargetBase = reinterpret_cast<BYTE*>(VirtualAlloc(NULL, pOptHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (!pTargetBase) return nullptr;

    // Copy Headers
    memcpy(pTargetBase, pSrcData, pOptHeader->SizeOfHeaders);

    // Copy Sections
    auto* pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);
    for (int i = 0; i < pNtHeader->FileHeader.NumberOfSections; ++i, ++pSectionHeader) {
        if (pSectionHeader->SizeOfRawData) {
            memcpy(pTargetBase + pSectionHeader->VirtualAddress, pSrcData + pSectionHeader->PointerToRawData, pSectionHeader->SizeOfRawData);
        }
    }

    // Fix up the DLL
    RebaseDll(pTargetBase, pNtHeader);
    if (!ResolveImports(pTargetBase, pNtHeader)) {
        VirtualFree(pTargetBase, 0, MEM_RELEASE);
        return nullptr;
    }

    // Clean up PE Headers (Optional)
    // memset(pTargetBase, 0, pOptHeader->SizeOfHeaders);

    return (HMODULE)pTargetBase;
}