#pragma once
#include <Windows.h>
#include <intrin.h>

// PEB-based module resolution — zero GetModuleHandle/GetProcAddress calls
namespace peb
{
    struct ModuleInfo {
        void* base;
        unsigned long size;
    };

    // Walk PEB InMemoryOrderModuleList to find a loaded module by name (case-insensitive)
    inline void* GetModuleBase(const char* name)
    {
        struct UNICODE_STR { USHORT Length; USHORT MaxLength; wchar_t* Buffer; };
        struct LDR_ENTRY {
            LIST_ENTRY InLoadOrder;
            LIST_ENTRY InMemoryOrder;
            LIST_ENTRY InInitOrder;
            void* DllBase;
            void* EntryPoint;
            ULONG SizeOfImage;
            ULONG Pad;
            UNICODE_STR FullDllName;
        };
        struct LDR_DATA { ULONG Length; BOOLEAN Init; BYTE Pad[3]; void* Ss; LIST_ENTRY InLoadOrder; LIST_ENTRY InMemoryOrder; };

        BYTE* pPeb = (BYTE*)__readgsqword(0x60);
        LDR_DATA* ldr = *(LDR_DATA**)(pPeb + 0x18);
        LIST_ENTRY* list = &ldr->InMemoryOrder;
        LIST_ENTRY* entry = list->Flink;

        while (entry != list)
        {
            LDR_ENTRY* mod = CONTAINING_RECORD(entry, LDR_ENTRY, InMemoryOrder);
            if (mod->FullDllName.Buffer)
            {
                wchar_t* fullPath = mod->FullDllName.Buffer;
                wchar_t* fileName = fullPath;
                for (wchar_t* p = fullPath; *p; p++)
                    if (*p == L'\\' || *p == L'/') fileName = p + 1;

                // Case-insensitive compare against name
                const char* n = name;
                const wchar_t* f = fileName;
                bool match = true;
                while (*n && *f)
                {
                    wchar_t fc = (*f >= L'A' && *f <= L'Z') ? (*f + 32) : *f;
                    char nc = (*n >= 'A' && *n <= 'Z') ? (*n + 32) : *n;
                    if (fc != (wchar_t)nc) { match = false; break; }
                    n++; f++;
                }
                if (match && *n == '\0' && *f == L'\0')
                    return mod->DllBase;
            }
            entry = entry->Flink;
        }
        return nullptr;
    }

    // Resolve an export by name from a module base (PE export directory walk)
    inline void* GetExportAddress(void* moduleBase, const char* exportName)
    {
        if (!moduleBase || !exportName) return nullptr;

        auto dos = (IMAGE_DOS_HEADER*)moduleBase;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;

        auto nt = (IMAGE_NT_HEADERS*)((uintptr_t)moduleBase + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;

        auto& exportDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
        if (!exportDir.VirtualAddress || !exportDir.Size) return nullptr;

        auto exports = (IMAGE_EXPORT_DIRECTORY*)((uintptr_t)moduleBase + exportDir.VirtualAddress);
        auto names   = (DWORD*)((uintptr_t)moduleBase + exports->AddressOfNames);
        auto ordinals = (WORD*)((uintptr_t)moduleBase + exports->AddressOfNameOrdinals);
        auto functions = (DWORD*)((uintptr_t)moduleBase + exports->AddressOfFunctions);

        for (DWORD i = 0; i < exports->NumberOfNames; i++)
        {
            const char* funcName = (const char*)((uintptr_t)moduleBase + names[i]);
            const char* a = funcName;
            const char* b = exportName;
            bool match = true;
            while (*a && *b) { if (*a++ != *b++) { match = false; break; } }
            if (match && *a == *b)
            {
                WORD ord = ordinals[i];
                uintptr_t rva = functions[ord];
                // Check for forwarded export (RVA falls within export directory)
                if (rva >= exportDir.VirtualAddress && rva < exportDir.VirtualAddress + exportDir.Size)
                    continue; // skip forwarded exports
                return (void*)((uintptr_t)moduleBase + rva);
            }
        }
        return nullptr;
    }

}
