#pragma once
#include <Windows.h>
#include "reloc.h"
#include "../comms/comms.h"
#include "../log/log.h"
#include "../log/fmt.h"

namespace ept
{
    // 234-byte full-context stub template (og.txt EPT_Hook_Shellcode_Stub).
    constexpr unsigned long long STUB_MAGIC = 0x1E38EDFF2301EEBCull;
    constexpr unsigned char STUB_TEMPLATE[] = {
        0x50,0x51,0x52,0x53,0x55,0x56,0x57,0x41,0x50,0x41,0x51,0x41,0x52,0x41,0x53,
        0x41,0x54,0x41,0x55,0x41,0x56,0x41,0x57,0x9C,0x48,0x89,0xCE,0x48,0x89,0xE1,
        0x48,0x81,0xC1,0x80,0x00,0x00,0x00,0x51,0x48,0x89,0xE1,0x48,0x89,0xE3,0x48,
        0x83,0xE4,0xF0,0x48,0x81,0xEC,0x00,0x02,0x00,0x00,0x0F,0xAE,0x04,0x24,0x0F,
        0x28,0xF5,0x0F,0x28,0xEC,0x0F,0x28,0xE3,0x0F,0x28,0xDA,0x0F,0x28,0xD1,0x0F,
        0x28,0xC8,0x48,0x8D,0xAB,0x88,0x00,0x00,0x00,0x48,0x83,0xC5,0x08,0x48,0x8B,
        0x45,0x40,0x50,0x48,0x8B,0x45,0x38,0x50,0x48,0x8B,0x45,0x30,0x50,0x48,0x8B,
        0x45,0x28,0x50,0x48,0x8B,0x45,0x20,0x50,0x41,0x51,0x4D,0x89,0xC1,0x49,0x89,
        0xD0,0x48,0x89,0xF2,0x48,0x83,0xEC,0x20,0x48,0xB8,0xBC,0xEE,0x01,0x23,0xFF,
        0xED,0x38,0x1E,0xFF,0xD0,0x48,0xBF,0xBC,0xEE,0x01,0x23,0xFF,0xED,0x38,0x1E,
        0x48,0x83,0xC4,0x20,0x48,0x83,0xC4,0x30,0x83,0xF8,0x00,0x74,0x00,0x0F,0xAE,
        0x0C,0x24,0x48,0x89,0xDC,0x48,0x83,0xC4,0x08,0x9D,0x41,0x5F,0x41,0x5E,0x41,
        0x5D,0x41,0x5C,0x41,0x5B,0x41,0x5A,0x41,0x59,0x41,0x58,0x5F,0x5E,0x5D,0x5B,
        0x5A,0x59,0x58,0xC3,0x0F,0xAE,0x0C,0x24,0x48,0x89,0xDC,0x48,0x83,0xC4,0x08,
        0x9D,0x41,0x5F,0x41,0x5E,0x41,0x5D,0x41,0x5C,0x41,0x5B,0x41,0x5A,0x41,0x59,
        0x41,0x58,0x5F,0x5E,0x5D,0x5B,0x5A,0x59,0x58,
    };
    constexpr unsigned int STUB_SIZE = sizeof(STUB_TEMPLATE);

    struct rip_fixup_entry_t
    {
        unsigned short offset_in_relocated;
        unsigned short instr_len_after_disp;
        unsigned long long abs_target;
    };

    struct ept_hook_install_params_t
    {
        unsigned int stub_size;
        unsigned int displaced_count;
        unsigned int relocated_size;
        unsigned int fixup_count;
        unsigned char patched_stub[256];
        unsigned char relocated_bytes[512];
        rip_fixup_entry_t fixups[16];
    };

    // Stub context — matches push order in ept_hook_stub
    struct register_context_t
    {
        unsigned long long original_rsp;
        unsigned long long rflags;
        unsigned long long r15, r14, r13, r12, r11, r10, r9, r8;
        unsigned long long rdi, rsi, rbp, rbx, rdx, rcx, rax;
    };

    inline void patch_stub(unsigned char* stub, unsigned int size, unsigned long long detour_va)
    {
        for (unsigned int i = 0; i + 8 <= size; i++)
        {
            if (*(unsigned long long*)(stub + i) == STUB_MAGIC)
                *(unsigned long long*)(stub + i) = detour_va;
        }
        for (unsigned int i = 0; i + 5 <= size; i++)
        {
            if (stub[i] == 0x83 && stub[i+1] == 0xF8 && stub[i+2] == 0x00 && stub[i+3] == 0x74)
            {
                stub[i+4] = 36;
                break;
            }
        }
    }

    // Page-aligned params — each caller gets their own via __declspec(align(4096))
    inline bool install_hook(ept_hook_install_params_t& params, unsigned char* target, void* detour, const char* name)
    {
        char buf[256];

        fmt::snprintf(buf, sizeof(buf), "[Ring-1] %s: %p\r\n", name, target);
        log::to_file(buf);

        // Follow JMP chain (including hot-patch NOPs before JMPs)
        for (int chain = 0; chain < 8; chain++)
        {
            // Skip lea rsp,[rsp] — 4-byte NOP used as hot-patch/alignment padding
            // Without this, EPT hook lands on dense thunk table and the 234-byte stub
            // overwrites neighboring thunks on the shadow page → crash
            if (target[0] == 0x48 && target[1] == 0x8D && target[2] == 0x24 && target[3] == 0x24)
            {
                target += 4;
                continue;
            }
            if (target[0] == 0xE9)
            {
                int rel = *(int*)(target + 1);
                unsigned char* next = target + 5 + rel;
                fmt::snprintf(buf, sizeof(buf), "[Ring-1] %s: E9 chain %p -> %p\r\n", name, target, next);
                log::to_file(buf);
                target = next;
            }
            else if (target[0] == 0xEB)
            {
                signed char rel = *(signed char*)(target + 1);
                target = target + 2 + rel;
            }
            else if (target[0] == 0xFF && target[1] == 0x25 && *(int*)(target + 2) == 0)
            {
                target = *(unsigned char**)(target + 6);
            }
            else
                break;
        }

        fmt::snprintf(buf, sizeof(buf),
            "[Ring-1] %s prologue: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X\r\n",
            name,
            target[0], target[1], target[2],  target[3],  target[4],
            target[5], target[6], target[7],  target[8],  target[9],
            target[10], target[11], target[12], target[13], target[14], target[15]);
        log::to_file(buf);

        auto reloc_result = reloc::relocate_displaced(target, (unsigned long long)target);
        if (!reloc_result.ok)
        {
            log::to_file("[Ring-1] FAIL: displaced byte relocation failed\r\n");
            return false;
        }

        for (unsigned int i = 0; i < STUB_SIZE; i++)
            params.patched_stub[i] = STUB_TEMPLATE[i];
        patch_stub(params.patched_stub, STUB_SIZE, (unsigned long long)detour);

        params.stub_size = STUB_SIZE;
        params.displaced_count = reloc_result.displaced_count;
        params.relocated_size = reloc_result.size;
        params.fixup_count = reloc_result.fixup_count;

        for (unsigned int i = 0; i < reloc_result.size; i++)
            params.relocated_bytes[i] = reloc_result.bytes[i];

        for (unsigned int i = 0; i < reloc_result.fixup_count; i++)
        {
            params.fixups[i].offset_in_relocated = reloc_result.fixups[i].offset_in_relocated;
            params.fixups[i].instr_len_after_disp = reloc_result.fixups[i].instr_len_after_disp;
            params.fixups[i].abs_target = reloc_result.fixups[i].abs_target;
        }

        implant_request_t req = {};
        req.command = CMD_INSTALL_EPT_HOOK;
        req.param1 = (unsigned long long)target;
        req.param2 = (unsigned long long)&params;

        ntclose_syscall(NTCLOSE_MAGIC, (unsigned long long)&req);

        fmt::snprintf(buf, sizeof(buf), "[Ring-1] %s hook: status=%u, result=%llu\r\n",
                  name, req.status, req.result);
        log::to_file(buf);

        return req.status == 0 && req.result != 0;
    }
}
