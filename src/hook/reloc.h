#pragma once
#include <cstdint>

namespace reloc
{
    // Minimal x64 instruction length decoder.
    // Returns instruction length, or 0 if unknown.
    inline int insn_len(const uint8_t* code)
    {
        const uint8_t* p = code;

        // Skip legacy prefixes
        for (;;)
        {
            uint8_t b = *p;
            if (b == 0xF0 || b == 0xF2 || b == 0xF3 ||  // LOCK, REPNE, REP
                b == 0x2E || b == 0x3E || b == 0x26 ||    // segment overrides
                b == 0x36 || b == 0x64 || b == 0x65 ||
                b == 0x66 || b == 0x67)                    // operand/address size
                p++;
            else
                break;
        }

        // REX prefix (40-4F)
        bool rex_w = false;
        if (*p >= 0x40 && *p <= 0x4F)
        {
            rex_w = (*p & 0x08) != 0;
            p++;
        }

        uint8_t op = *p++;
        bool has_modrm = false;
        int imm_size = 0;

        if (op == 0x0F)
        {
            // Two-byte opcode
            uint8_t op2 = *p++;

            if (op2 >= 0x80 && op2 <= 0x8F)
            {
                // Jcc rel32
                imm_size = 4;
            }
            else if (op2 == 0xBA)
            {
                // BT/BTS/BTR/BTC Ev,Ib
                has_modrm = true;
                imm_size = 1;
            }
            else if (op2 == 0xA4 || op2 == 0xAC || op2 == 0xC2 || op2 == 0xC4 ||
                     op2 == 0xC5 || op2 == 0xC6)
            {
                // SHLD/SHRD imm8, CMPSS/PD, PINSRW, SHUFPS/PD
                has_modrm = true;
                imm_size = 1;
            }
            else if ((op2 >= 0x10 && op2 <= 0x17) ||   // SSE mov
                     (op2 >= 0x28 && op2 <= 0x2F) ||   // SSE movaps/comiss
                     (op2 >= 0x40 && op2 <= 0x4F) ||   // CMOVcc
                     (op2 >= 0x50 && op2 <= 0x6F) ||   // SSE various
                     (op2 >= 0x70 && op2 <= 0x7F) ||   // SSE various
                     (op2 >= 0x90 && op2 <= 0x9F) ||   // SETcc
                     (op2 >= 0xA3 && op2 <= 0xAF) ||   // BT/SHLD/IMUL/etc
                     (op2 >= 0xB0 && op2 <= 0xBF) ||   // CMPXCHG/MOVZX/MOVSX/etc
                     op2 == 0x00 || op2 == 0x01 ||     // SLDT/SGDT group
                     op2 == 0xAE || op2 == 0x1F)       // FXSAVE/NOP
            {
                has_modrm = true;
            }
            else
            {
                return 0; // unknown 2-byte opcode
            }
        }
        else
        {
            // One-byte opcode
            // ALU groups: 00-05, 08-0D, 10-15, 18-1D, 20-25, 28-2D, 30-35, 38-3D
            uint8_t group_base = op & 0xF8;
            uint8_t group_off = op & 0x07;
            if (group_base <= 0x38 && (group_base & 0x06) == 0)
            {
                if (group_off <= 3) has_modrm = true;
                else if (group_off == 4) imm_size = 1;
                else if (group_off == 5) imm_size = 4;
                else return 0; // 06/07/0E/etc invalid in 64-bit
            }
            else if (op >= 0x50 && op <= 0x5F)
            {
                // PUSH/POP reg — 1 byte (already consumed)
            }
            else if (op == 0x63)
            {
                has_modrm = true; // MOVSXD
            }
            else if (op == 0x68)
            {
                imm_size = 4; // PUSH imm32
            }
            else if (op == 0x69)
            {
                has_modrm = true; imm_size = 4; // IMUL Gv,Ev,Iz
            }
            else if (op == 0x6A)
            {
                imm_size = 1; // PUSH imm8
            }
            else if (op == 0x6B)
            {
                has_modrm = true; imm_size = 1; // IMUL Gv,Ev,Ib
            }
            else if (op >= 0x70 && op <= 0x7F)
            {
                imm_size = 1; // Jcc rel8
            }
            else if (op == 0x80 || op == 0x82)
            {
                has_modrm = true; imm_size = 1; // ALU Eb,Ib
            }
            else if (op == 0x81)
            {
                has_modrm = true; imm_size = 4; // ALU Ev,Iz
            }
            else if (op == 0x83)
            {
                has_modrm = true; imm_size = 1; // ALU Ev,Ib
            }
            else if ((op >= 0x84 && op <= 0x8E) || op == 0x8D)
            {
                has_modrm = true; // TEST/XCHG/MOV/LEA
            }
            else if (op == 0x8F)
            {
                has_modrm = true; // POP Ev
            }
            else if (op >= 0x90 && op <= 0x97)
            {
                // NOP / XCHG rAX,reg
            }
            else if (op == 0x98 || op == 0x99 || op == 0x9C || op == 0x9D ||
                     op == 0x9E || op == 0x9F)
            {
                // CBW/CWD/PUSHF/POPF/SAHF/LAHF
            }
            else if (op >= 0xA0 && op <= 0xA3)
            {
                // MOV with moffs — 8-byte address in 64-bit mode
                imm_size = 8;
            }
            else if (op == 0xA8)
            {
                imm_size = 1; // TEST AL,Ib
            }
            else if (op == 0xA9)
            {
                imm_size = 4; // TEST rAX,Iz
            }
            else if (op >= 0xB0 && op <= 0xB7)
            {
                imm_size = 1; // MOV r8,Ib
            }
            else if (op >= 0xB8 && op <= 0xBF)
            {
                imm_size = rex_w ? 8 : 4; // MOV r32/r64,Iv
            }
            else if (op == 0xC0 || op == 0xC1)
            {
                has_modrm = true; imm_size = 1; // shift Eb/Ev,Ib
            }
            else if (op == 0xC2)
            {
                imm_size = 2; // RETN imm16
            }
            else if (op == 0xC3)
            {
                // RETN
            }
            else if (op == 0xC6)
            {
                has_modrm = true; imm_size = 1; // MOV Eb,Ib
            }
            else if (op == 0xC7)
            {
                has_modrm = true; imm_size = 4; // MOV Ev,Iz
            }
            else if (op == 0xCC || op == 0xCD)
            {
                if (op == 0xCD) imm_size = 1; // INT n
            }
            else if (op >= 0xD0 && op <= 0xD3)
            {
                has_modrm = true; // shift group
            }
            else if (op == 0xE8 || op == 0xE9)
            {
                imm_size = 4; // CALL/JMP rel32
            }
            else if (op == 0xEB)
            {
                imm_size = 1; // JMP rel8
            }
            else if (op == 0xF6)
            {
                has_modrm = true;
                // TEST Eb,Ib has imm8, others (NOT/NEG/MUL/DIV) don't
                // We need to peek at ModRM.reg to know — defer to caller
                // For safety, assume no immediate (TEST is uncommon in prologues)
            }
            else if (op == 0xF7)
            {
                has_modrm = true;
                // Same as F6 but with imm32 for TEST
            }
            else if (op == 0xFE || op == 0xFF)
            {
                has_modrm = true; // INC/DEC/CALL/JMP/PUSH
            }
            else
            {
                return 0; // unknown
            }
        }

        // Parse ModRM if present
        if (has_modrm)
        {
            uint8_t modrm = *p++;
            uint8_t mod = (modrm >> 6) & 3;
            uint8_t rm = modrm & 7;

            if (mod == 0)
            {
                if (rm == 4) p++; // SIB byte
                if (rm == 5) p += 4; // [RIP+disp32]
            }
            else if (mod == 1)
            {
                if (rm == 4) p++; // SIB byte
                p += 1; // disp8
            }
            else if (mod == 2)
            {
                if (rm == 4) p++; // SIB byte
                p += 4; // disp32
            }
            // mod == 3: register, no displacement
        }

        p += imm_size;

        return (int)(p - code);
    }

    // Check if instruction at `code` has RIP-relative addressing ([RIP+disp32]).
    // Returns offset to the disp32 within the instruction, or 0 if not RIP-relative.
    inline int find_rip_disp_offset(const uint8_t* code, int len)
    {
        const uint8_t* p = code;

        // Skip prefixes
        while (*p == 0xF0 || *p == 0xF2 || *p == 0xF3 ||
               *p == 0x2E || *p == 0x3E || *p == 0x26 ||
               *p == 0x36 || *p == 0x64 || *p == 0x65 ||
               *p == 0x66 || *p == 0x67)
            p++;

        // Skip REX
        if (*p >= 0x40 && *p <= 0x4F) p++;

        uint8_t op = *p++;

        // Two-byte opcode
        if (op == 0x0F) p++;

        // These opcodes don't have ModRM (they use immediate offsets)
        if (op == 0xE8 || op == 0xE9 || op == 0xEB) return 0;
        if (op >= 0x70 && op <= 0x7F) return 0;
        if (op == 0x0F) return 0; // Jcc rel32 handled separately

        // Check ModRM: mod=00, rm=101 → [RIP+disp32]
        if ((int)(p - code) < len)
        {
            uint8_t modrm = *p;
            uint8_t mod = (modrm >> 6) & 3;
            uint8_t rm = modrm & 7;

            if (mod == 0 && rm == 5)
            {
                // disp32 starts at p+1
                return (int)(p + 1 - code);
            }
        }

        return 0;
    }

    struct relocated_result_t
    {
        uint8_t  bytes[512];
        uint32_t size;
        uint32_t displaced_count; // original bytes consumed (>= 14, at instruction boundary)
        bool     ok;
    };

    // Relocate displaced bytes from `target` for execution at any address.
    // Walks instructions until >= 14 bytes consumed, fixing RIP-relative operands.
    // E9 rel32 → 14-byte absolute JMP (push/ret)
    // E8 rel32 → 14-byte absolute JMP with return addr fixup (not supported yet, returns !ok)
    // [RIP+disp32] → adjusted to point to original absolute address
    //   NOTE: disp32 adjustment requires knowing destination address.
    //   We store the absolute address and let kernel patch the disp32 at install time.
    //   For simplicity, we convert [RIP+disp32] to use an absolute address encoding.
    //
    // For [RIP+disp32], since we can't know the destination address, we record
    // the fixup entries and the kernel implant applies them.
    //
    // Actually: simpler approach — we DON'T try to fix [RIP+disp32] in the DLL.
    // Instead, we send relocation entries and the kernel applies them.
    // But that complicates the kernel. So: just record absolute targets and
    // the kernel fixes disp32 = abs_target - (dest_rip + instr_len_from_modrm).
    //
    // SIMPLEST approach for now: handle E9/EB (JMP) and E8 (CALL) which change size.
    // For [RIP+disp32] data references, record fixup entries in the struct.

    struct rip_fixup_t
    {
        uint16_t offset_in_relocated;  // where the disp32 is in relocated bytes
        uint16_t instr_len_after_disp; // bytes after disp32 to end of instruction (usually 0)
        uint64_t abs_target;           // absolute address the disp32 should point to
    };

    struct full_reloc_result_t
    {
        uint8_t     bytes[512];
        uint32_t    size;
        uint32_t    displaced_count;
        rip_fixup_t fixups[16];
        uint32_t    fixup_count;
        bool        ok;
    };

    inline void write_abs_jmp(uint8_t* dest, uint64_t target)
    {
        uint32_t lo = (uint32_t)(target & 0xFFFFFFFF);
        uint32_t hi = (uint32_t)(target >> 32);
        dest[0] = 0x68;
        *(uint32_t*)(dest + 1) = lo;
        dest[5] = 0xC7; dest[6] = 0x44; dest[7] = 0x24; dest[8] = 0x04;
        *(uint32_t*)(dest + 9) = hi;
        dest[13] = 0xC3;
    }

    inline full_reloc_result_t relocate_displaced(const uint8_t* target, uint64_t target_va)
    {
        full_reloc_result_t result = {};
        result.ok = false;

        uint32_t src_off = 0;  // offset in original code
        uint32_t dst_off = 0;  // offset in relocated bytes

        while (src_off < 14)
        {
            int len = insn_len(target + src_off);
            if (len == 0 || dst_off + 32 > sizeof(result.bytes))
                return result; // decode failed

            uint8_t op = target[src_off];
            // Check for REX prefix
            const uint8_t* insn_start = target + src_off;
            const uint8_t* p = insn_start;
            // Skip prefixes to find actual opcode
            while (*p == 0xF0 || *p == 0xF2 || *p == 0xF3 ||
                   *p == 0x2E || *p == 0x3E || *p == 0x26 ||
                   *p == 0x36 || *p == 0x64 || *p == 0x65 ||
                   *p == 0x66 || *p == 0x67)
                p++;
            if (*p >= 0x40 && *p <= 0x4F) p++;
            uint8_t actual_op = *p;

            if (actual_op == 0xE9)
            {
                // JMP rel32 → absolute 14-byte JMP
                int32_t rel = *(int32_t*)(p + 1);
                uint64_t abs_target = target_va + src_off + len + rel;
                write_abs_jmp(result.bytes + dst_off, abs_target);
                dst_off += 14;
                src_off += len;
            }
            else if (actual_op == 0xEB)
            {
                // JMP rel8 → absolute 14-byte JMP
                int8_t rel = *(int8_t*)(p + 1);
                uint64_t abs_target = target_va + src_off + len + rel;
                write_abs_jmp(result.bytes + dst_off, abs_target);
                dst_off += 14;
                src_off += len;
            }
            else if (actual_op >= 0x70 && actual_op <= 0x7F)
            {
                // Jcc rel8 → inverted Jcc rel32 + 14-byte absolute JMP
                //
                // Problem: trampoline is in PML4[128] (0x4000'xxxx'xxxx),
                // original code is in normal user space (0x1'xxxx'xxxx).
                // Distance is ~70TB — far beyond ±2GB rel32 limit.
                //
                // Solution: invert the condition to skip over an absolute JMP.
                // If original JS would be TAKEN → inverted JNS is NOT taken
                //   → falls through to 14-byte abs JMP → reaches target ✓
                // If original JS would NOT be taken → inverted JNS IS taken
                //   → skips abs JMP → continues to next instruction ✓
                //
                // Layout: [inverted_Jcc_rel32 +14] [14-byte abs JMP to target]
                //         6 bytes                   14 bytes = 20 total
                int8_t rel8 = *(int8_t*)(p + 1);
                uint64_t abs_target = target_va + src_off + len + rel8;

                // Inverted condition: toggle bit 0 of condition code
                // JS(8)→JNS(9), JAE(3)→JB(2), JE(4)→JNE(5), etc.
                uint8_t inverted_cc = (actual_op & 0x0F) ^ 0x01;
                uint8_t near_inv_cc = 0x80 | inverted_cc;

                // Emit inverted Jcc rel32 that skips 14 bytes (the abs JMP)
                result.bytes[dst_off]     = 0x0F;
                result.bytes[dst_off + 1] = near_inv_cc;
                *(int32_t*)(result.bytes + dst_off + 2) = 14; // skip abs JMP
                dst_off += 6;

                // Emit 14-byte absolute JMP to original target
                write_abs_jmp(result.bytes + dst_off, abs_target);
                dst_off += 14;

                src_off += len;
            }
            else if (actual_op == 0x0F && (*(p + 1) >= 0x80 && *(p + 1) <= 0x8F))
            {
                // Two-byte Jcc rel32 (0F 80-8F) → inverted Jcc rel32 + 14-byte absolute JMP
                // Same >2GB problem as Jcc rel8 — trampoline is in PML4[128].
                uint8_t cc = *(p + 1) & 0x0F;
                int32_t rel32 = *(int32_t*)(p + 2);
                uint64_t abs_target = target_va + src_off + len + rel32;

                // Inverted condition: toggle bit 0
                uint8_t inv_cc = cc ^ 0x01;

                // Emit inverted Jcc rel32 that skips 14 bytes (the abs JMP)
                result.bytes[dst_off]     = 0x0F;
                result.bytes[dst_off + 1] = 0x80 | inv_cc;
                *(int32_t*)(result.bytes + dst_off + 2) = 14; // skip abs JMP
                dst_off += 6;

                // Emit 14-byte absolute JMP to original target
                write_abs_jmp(result.bytes + dst_off, abs_target);
                dst_off += 14;

                src_off += len;
            }
            else if (actual_op == 0xE8)
            {
                // CALL rel32 → absolute indirect CALL + inline target.
                //
                // Trampoline is in PML4[128] (~70TB from the module), so we can't
                // keep a rel32 CALL — convert to `call qword ptr [rip+2]` with the
                // absolute target stored in 8 bytes right after a 2-byte JMP that
                // steps over them.
                //
                //   FF 15 02 00 00 00        ; call qword ptr [rip+2]     (6 bytes)
                //   EB 08                     ; jmp +8 (skip abs target)  (2 bytes)
                //   <8 bytes abs_target>                                   (8 bytes)
                // Total: 16 bytes.
                //
                // When executed:
                //   1. CALL pushes return = dst+6, jumps to *(dst+8) = abs_target
                //   2. Callee RETs → returns to dst+6 (the JMP +8)
                //   3. JMP lands at dst+16 (just past the 8-byte target literal)
                //   4. Execution continues with the next relocated instruction.
                int32_t rel32 = *reinterpret_cast<const int32_t*>(p + 1);
                uint64_t abs_target = target_va + src_off + len + rel32;

                result.bytes[dst_off + 0] = 0xFF;
                result.bytes[dst_off + 1] = 0x15;
                *reinterpret_cast<uint32_t*>(result.bytes + dst_off + 2) = 2u;

                result.bytes[dst_off + 6] = 0xEB;
                result.bytes[dst_off + 7] = 0x08;

                *reinterpret_cast<uint64_t*>(result.bytes + dst_off + 8) = abs_target;

                dst_off += 16;
                src_off += len;
            }
            else
            {
                // Check for [RIP+disp32]
                int disp_off = find_rip_disp_offset(insn_start, len);
                if (disp_off > 0)
                {
                    // Copy instruction, record fixup
                    for (int i = 0; i < len; i++)
                        result.bytes[dst_off + i] = insn_start[i];

                    int32_t orig_disp = *(int32_t*)(insn_start + disp_off);
                    uint64_t abs_target = target_va + src_off + len + orig_disp;

                    if (result.fixup_count < 16)
                    {
                        result.fixups[result.fixup_count].offset_in_relocated = (uint16_t)(dst_off + disp_off);
                        result.fixups[result.fixup_count].instr_len_after_disp = (uint16_t)(len - disp_off - 4);
                        result.fixups[result.fixup_count].abs_target = abs_target;
                        result.fixup_count++;
                    }

                    dst_off += len;
                    src_off += len;
                }
                else
                {
                    // No RIP-relative addressing — copy raw
                    for (int i = 0; i < len; i++)
                        result.bytes[dst_off + i] = insn_start[i];
                    dst_off += len;
                    src_off += len;
                }
            }
        }

        result.size = dst_off;
        result.displaced_count = src_off;
        result.ok = true;
        return result;
    }
}
