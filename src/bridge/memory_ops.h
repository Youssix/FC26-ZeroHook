#pragma once
#include <Windows.h>
#include "../peb/peb.h"

namespace bridge {

    // ── Win32 function typedefs ──────────────────────────────────────────
    typedef SIZE_T(__stdcall* fnVirtualQuery)(LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T);
    typedef BOOL(__stdcall* fnVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
    typedef LPVOID(__stdcall* fnVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
    typedef BOOL(__stdcall* fnVirtualFree)(LPVOID, SIZE_T, DWORD);

    // ── Lazy-resolved API pointers ───────────────────────────────────────
    struct MemApis {
        fnVirtualQuery  pVirtualQuery;
        fnVirtualProtect pVirtualProtect;
        fnVirtualAlloc  pVirtualAlloc;
        fnVirtualFree   pVirtualFree;
        bool resolved;
    };

    inline MemApis& memApis()
    {
        static MemApis apis = {};
        if (!apis.resolved) {
            void* k32 = peb::GetModuleBase("kernel32.dll");
            if (k32) {
                apis.pVirtualQuery   = (fnVirtualQuery)peb::GetExportAddress(k32, "VirtualQuery");
                apis.pVirtualProtect = (fnVirtualProtect)peb::GetExportAddress(k32, "VirtualProtect");
                apis.pVirtualAlloc   = (fnVirtualAlloc)peb::GetExportAddress(k32, "VirtualAlloc");
                apis.pVirtualFree    = (fnVirtualFree)peb::GetExportAddress(k32, "VirtualFree");
                apis.resolved = true;
            }
        }
        return apis;
    }

    // ── Inline string/memory helpers (no CRT) ────────────────────────────
    inline int strLen(const char* s)
    {
        int n = 0;
        while (s[n]) n++;
        return n;
    }

    inline void memCopy(void* dst, const void* src, int size)
    {
        auto d = (unsigned char*)dst;
        auto s = (const unsigned char*)src;
        for (int i = 0; i < size; i++) d[i] = s[i];
    }

    inline void memZero(void* dst, int size)
    {
        auto d = (unsigned char*)dst;
        for (int i = 0; i < size; i++) d[i] = 0;
    }

    inline int strCmp(const char* a, const char* b)
    {
        while (*a && *b) {
            if (*a != *b) return *a - *b;
            a++; b++;
        }
        return *a - *b;
    }

    inline int strNCmp(const char* a, const char* b, int n)
    {
        for (int i = 0; i < n; i++) {
            if (a[i] != b[i]) return a[i] - b[i];
            if (!a[i]) return 0;
        }
        return 0;
    }

    // ── Hex encode/decode ────────────────────────────────────────────────
    inline int hexEncode(const void* data, int size, char* out, int outMax)
    {
        const char* digits = "0123456789ABCDEF";
        auto src = (const unsigned char*)data;
        int pos = 0;
        for (int i = 0; i < size && pos + 2 < outMax; i++) {
            out[pos++] = digits[(src[i] >> 4) & 0xF];
            out[pos++] = digits[src[i] & 0xF];
        }
        if (pos < outMax) out[pos] = '\0';
        return pos;
    }

    inline int hexVal(char c)
    {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        return -1;
    }

    inline int hexDecode(const char* hex, int hexLen, void* out, int outMax)
    {
        auto dst = (unsigned char*)out;
        int pos = 0;
        for (int i = 0; i + 1 < hexLen && pos < outMax; i += 2) {
            int hi = hexVal(hex[i]);
            int lo = hexVal(hex[i + 1]);
            if (hi < 0 || lo < 0) return -1;
            dst[pos++] = (unsigned char)((hi << 4) | lo);
        }
        return pos;
    }

    inline uintptr_t parseHex(const char* str, int len)
    {
        uintptr_t val = 0;
        for (int i = 0; i < len; i++) {
            int v = hexVal(str[i]);
            if (v < 0) break;
            val = (val << 4) | v;
        }
        return val;
    }

    // ── Simple atof (no scientific notation) ─────────────────────────────
    inline float parseFloat(const char* str, int len)
    {
        if (len <= 0) return 0.0f;
        bool neg = false;
        int i = 0;
        if (str[i] == '-') { neg = true; i++; }
        else if (str[i] == '+') { i++; }

        float intPart = 0.0f;
        while (i < len && str[i] >= '0' && str[i] <= '9') {
            intPart = intPart * 10.0f + (float)(str[i] - '0');
            i++;
        }

        float fracPart = 0.0f;
        if (i < len && str[i] == '.') {
            i++;
            float divisor = 10.0f;
            while (i < len && str[i] >= '0' && str[i] <= '9') {
                fracPart += (float)(str[i] - '0') / divisor;
                divisor *= 10.0f;
                i++;
            }
        }

        float result = intPart + fracPart;
        return neg ? -result : result;
    }

    // ── Memory read with SEH ─────────────────────────────────────────────
    inline int readMemory(uintptr_t address, void* buffer, int size)
    {
        if (address < 0x10000 || size <= 0) return 0;

        int bytesRead = 0;
        __try {
            memCopy(buffer, (const void*)address, size);
            bytesRead = size;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            bytesRead = 0;
        }
        return bytesRead;
    }

    // ── Memory write with VirtualProtect ─────────────────────────────────
    inline int writeMemory(uintptr_t address, const void* data, int size)
    {
        if (address < 0x10000 || size <= 0) return 0;
        auto& apis = memApis();
        if (!apis.pVirtualProtect) return 0;

        DWORD oldProtect = 0;
        if (!apis.pVirtualProtect((LPVOID)address, size, PAGE_EXECUTE_READWRITE, &oldProtect))
            return 0;

        int written = 0;
        __try {
            memCopy((void*)address, data, size);
            written = size;
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            written = 0;
        }

        apis.pVirtualProtect((LPVOID)address, size, oldProtect, &oldProtect);
        return written;
    }

    // ── Scan state ───────────────────────────────────────────────────────
    struct ScanState {
        uintptr_t* addresses;
        float*     values;
        int        count;
        int        capacity;
        int        valueSize;
    };

    inline void scanReset(ScanState* state)
    {
        auto& apis = memApis();
        if (!apis.pVirtualFree) return;
        if (state->addresses) { apis.pVirtualFree(state->addresses, 0, MEM_RELEASE); state->addresses = nullptr; }
        if (state->values)    { apis.pVirtualFree(state->values, 0, MEM_RELEASE);    state->values = nullptr; }
        state->count = 0;
        state->capacity = 0;
        state->valueSize = 4;
    }

    // ── Initial scan: walk all readable pages for a float value ──────────
    inline int scanInit(ScanState* state, float targetValue)
    {
        auto& apis = memApis();
        if (!apis.pVirtualAlloc || !apis.pVirtualQuery || !apis.pVirtualFree) return 0;

        // Free any previous scan
        scanReset(state);

        // Allocate candidate buffers: 1M entries = 8MB addresses + 4MB values
        const int maxEntries = 1024 * 1024;
        state->addresses = (uintptr_t*)apis.pVirtualAlloc(nullptr, maxEntries * sizeof(uintptr_t),
                                                          MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        state->values = (float*)apis.pVirtualAlloc(nullptr, maxEntries * sizeof(float),
                                                   MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!state->addresses || !state->values) {
            scanReset(state);
            return 0;
        }
        state->capacity = maxEntries;
        state->valueSize = 4;
        state->count = 0;

        const float epsilon = 0.0001f;
        MEMORY_BASIC_INFORMATION mbi;
        uintptr_t addr = 0x10000;

        while (addr < 0x7FFFFFFFFFFF) {
            if (apis.pVirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi)) == 0)
                break;

            if (mbi.State == MEM_COMMIT &&
                !(mbi.Protect & PAGE_GUARD) &&
                !(mbi.Protect & PAGE_NOACCESS) &&
                (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE | PAGE_EXECUTE_READ |
                                PAGE_EXECUTE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY)))
            {
                uintptr_t regionBase = (uintptr_t)mbi.BaseAddress;
                uintptr_t regionEnd = regionBase + mbi.RegionSize;

                for (uintptr_t p = regionBase; p + 4 <= regionEnd; p += 4) {
                    if (state->count >= state->capacity) goto done;

                    __try {
                        float val = *(float*)p;
                        float diff = val - targetValue;
                        if (diff < 0) diff = -diff;
                        if (diff < epsilon) {
                            state->addresses[state->count] = p;
                            state->values[state->count] = val;
                            state->count++;
                        }
                    }
                    __except (EXCEPTION_EXECUTE_HANDLER) {
                        // Skip this address
                    }
                }
            }

            uintptr_t next = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
            if (next <= addr) break;
            addr = next;
        }

    done:
        return state->count;
    }

    // ── Filter: keep only changed ────────────────────────────────────────
    inline int scanChanged(ScanState* state)
    {
        int write = 0;
        for (int i = 0; i < state->count; i++) {
            __try {
                float cur = *(float*)state->addresses[i];
                float diff = cur - state->values[i];
                if (diff < 0) diff = -diff;
                if (diff > 0.0001f) {
                    state->addresses[write] = state->addresses[i];
                    state->values[write] = cur;
                    write++;
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                // Address no longer readable, drop it
            }
        }
        state->count = write;
        return state->count;
    }

    // ── Filter: keep only unchanged ──────────────────────────────────────
    inline int scanUnchanged(ScanState* state)
    {
        int write = 0;
        for (int i = 0; i < state->count; i++) {
            __try {
                float cur = *(float*)state->addresses[i];
                float diff = cur - state->values[i];
                if (diff < 0) diff = -diff;
                if (diff <= 0.0001f) {
                    state->addresses[write] = state->addresses[i];
                    state->values[write] = cur;
                    write++;
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                // Drop inaccessible
            }
        }
        state->count = write;
        return state->count;
    }

    // ── Filter: keep only matching exact value ───────────────────────────
    inline int scanExact(ScanState* state, float targetValue)
    {
        const float epsilon = 0.0001f;
        int write = 0;
        for (int i = 0; i < state->count; i++) {
            __try {
                float cur = *(float*)state->addresses[i];
                float diff = cur - targetValue;
                if (diff < 0) diff = -diff;
                if (diff < epsilon) {
                    state->addresses[write] = state->addresses[i];
                    state->values[write] = cur;
                    write++;
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                // Drop inaccessible
            }
        }
        state->count = write;
        return state->count;
    }

} // namespace bridge
