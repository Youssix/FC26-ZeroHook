#include "game.h"
#include "../log/log.h"
#include "../log/fmt.h"

namespace
{
    typedef struct _R1_UNICODE_STRING {
        USHORT Length;
        USHORT MaximumLength;
        wchar_t* Buffer;
    } R1_UNICODE_STRING;

    typedef struct _R1_PEB_LDR_DATA {
        ULONG     Length;
        BOOLEAN   Initialized;
        BYTE      Padding[3];
        void*     SsHandle;
        LIST_ENTRY InLoadOrderModuleList;
        LIST_ENTRY InMemoryOrderModuleList;
    } R1_PEB_LDR_DATA;

    typedef struct _R1_LDR_DATA_TABLE_ENTRY {
        LIST_ENTRY InLoadOrderLinks;
        LIST_ENTRY InMemoryOrderLinks;
        LIST_ENTRY InInitializationOrderLinks;
        void*      DllBase;
        void*      EntryPoint;
        ULONG      SizeOfImage;
        ULONG      _Pad;
        R1_UNICODE_STRING FullDllName;
    } R1_LDR_DATA_TABLE_ENTRY;
}

namespace
{
    void parse_sig(const char* sig, unsigned char* pattern, char* mask, int* out_len)
    {
        int idx = 0;
        const char* p = sig;
        while (*p)
        {
            if (*p == ' ') { p++; continue; }
            if (*p == '?')
            {
                p++;
                if (*p == '?') p++;
                pattern[idx] = 0;
                mask[idx] = '?';
                idx++;
            }
            else
            {
                unsigned char val = 0;
                for (int i = 0; i < 2 && *p && *p != ' '; i++, p++)
                {
                    val <<= 4;
                    if (*p >= '0' && *p <= '9') val |= (*p - '0');
                    else if (*p >= 'A' && *p <= 'F') val |= (*p - 'A' + 10);
                    else if (*p >= 'a' && *p <= 'f') val |= (*p - 'a' + 10);
                }
                pattern[idx] = val;
                mask[idx] = 'x';
                idx++;
            }
        }
        *out_len = idx;
    }

}

void* game::pattern_scan(void* module_base, unsigned long module_size, const char* sig)
{
    unsigned char pattern[128];
    char mask[128];
    int pat_len = 0;
    parse_sig(sig, pattern, mask, &pat_len);
    if (pat_len == 0 || pat_len > 128) return nullptr;

    // Linear scan across the entire module (all sections including .shared)
    uintptr_t scan_base = (uintptr_t)module_base;
    uintptr_t scan_end = scan_base + module_size;

    for (uintptr_t addr = scan_base; addr + pat_len <= scan_end; addr++)
    {
        bool found = true;
        for (int j = 0; j < pat_len; j++)
        {
            if (mask[j] != '?' && pattern[j] != *(unsigned char*)(addr + j))
            {
                found = false;
                break;
            }
        }
        if (found) return (void*)addr;
    }
    return nullptr;
}

game::ModuleInfo game::find_module()
{
    BYTE* peb = (BYTE*)__readgsqword(0x60);
    R1_PEB_LDR_DATA* ldr = *(R1_PEB_LDR_DATA**)(peb + 0x18);
    LIST_ENTRY* list = &ldr->InMemoryOrderModuleList;
    LIST_ENTRY* entry = list->Flink;

    const wchar_t* targets[] = {
        L"fc26.exe",
        L"fc26_trial.exe",
        L"fc26_showcase.exe"
    };

    while (entry != list)
    {
        R1_LDR_DATA_TABLE_ENTRY* mod = CONTAINING_RECORD(entry, R1_LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        if (mod->FullDllName.Buffer)
        {
            wchar_t* fullPath = mod->FullDllName.Buffer;
            wchar_t* fileName = fullPath;
            for (wchar_t* p = fullPath; *p; p++)
            {
                if (*p == L'\\' || *p == L'/') fileName = p + 1;
            }

            for (int i = 0; i < 3; i++)
            {
                const wchar_t* t = targets[i];
                const wchar_t* f = fileName;
                bool match = true;
                while (*t)
                {
                    wchar_t fc = (*f >= L'A' && *f <= L'Z') ? (*f + 32) : *f;
                    if (fc != *t) { match = false; break; }
                    t++; f++;
                }
                if (match && *f == L'\0')
                {
                    return { mod->DllBase, mod->SizeOfImage };
                }
            }
        }
        entry = entry->Flink;
    }
    return { nullptr, 0 };
}
