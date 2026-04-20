#pragma once
#include <Windows.h>
#include <intrin.h>
#include "memory_ops.h"
#include "../comms/comms.h"
#include "../hook/ept_hook.h"
#include "../log/log.h"
#include "../log/fmt.h"

// Execute breakpoints over EPT hooks. Each BP shares the same logger detour
// shape but uses a unique templated wrapper so the C function knows which
// slot fired (without round-tripping through the trap_frame). Wrappers live
// in this DLL's .text — the kernel implant copies the patched stub into a
// hypervisor-managed runtime_heap page invisible to guest scans, so no
// VirtualAlloc/RWX allocation in the bridge process.
//
// Hot path (per BP fire):
//   guest hits target → EPT split routes to stub → stub saves regs →
//   stub calls bp_wrapper<Id> → wrapper calls common_logger(ctx, Id) →
//   common_logger writes one ring entry → return 0 → stub restores →
//   stub jumps to relocated displaced bytes → guest resumes.
//
// No mutex on the ring; a single InterlockedIncrement64 sequences slots.

namespace bridge_bp {

    // Fixed slot count — bigger means more .data and more template
    // instantiations, but each slot is just a pointer in the wrapper table
    // and a page-aligned params struct. 64 covers anything we'd realistically
    // arm at once.
    constexpr int  MAX_BPS        = 64;
    constexpr int  RING_CAPACITY  = 1024;
    constexpr unsigned long long RING_MASK = RING_CAPACITY - 1;

    // Per-event captured state. Packed for stable on-wire layout when hex-
    // encoded and sent over the pipe to the Python MCP.
    // Layout (192 bytes):
    //   tsc(8) target_va(8) original_rsp(8) rflags(8) = 32
    //   rax..rdi (7 GPRs) = 56  → cumulative 88
    //   r8..r15  (8 GPRs) = 64  → cumulative 152
    //   stack[4] = 32           → cumulative 184
    //   bp_id(2) cpu_id(2) reserved(4) = 8 → cumulative 192
#pragma pack(push, 1)
    struct bp_event_t {
        unsigned long long tsc;
        unsigned long long target_va;     // RIP at hit (== install target after JMP-chain follow)
        unsigned long long original_rsp;
        unsigned long long rflags;
        unsigned long long rax, rcx, rdx, rbx, rbp, rsi, rdi;
        unsigned long long r8, r9, r10, r11, r12, r13, r14, r15;
        unsigned long long stack[4];      // first 4 return addresses from saved RSP
        unsigned short     bp_id;
        unsigned short     cpu_id;
        unsigned int       reserved;
    };
    static_assert(sizeof(bp_event_t) == 192, "bp_event_t layout drift");
#pragma pack(pop)

    // Per-BP slot. Holds the EPT hook params (must be page-aligned), the
    // resolved target VA, runtime enable bit, and counters.
    struct bp_slot_t {
        bool                installed;
        bool                count_only;     // skip ring write, only bump hits
        volatile long       enabled;        // toggle without remove/install
        unsigned long long  target_va;
        volatile long long  hits;
        volatile long long  dropped;
    };

    // Forward decls so the wrappers can refer to common_logger.
    inline unsigned long long common_logger(ept::register_context_t* ctx, int bp_id);

    // Templated wrapper — one instantiation per slot id. __declspec(noinline)
    // forces the compiler to emit a distinct function body per Id so
    // &bp_wrapper<N> gives a distinct address suitable as the EPT detour.
    // No `extern "C"`: function templates can't have C linkage (each Id would
    // need a unique C symbol). install_hook takes a void*, so C linkage isn't
    // required anyway.
    template<int Id>
    __declspec(noinline)
    unsigned long long __fastcall bp_wrapper(ept::register_context_t* ctx)
    {
        return common_logger(ctx, Id);
    }

    // Page-aligned wrapper around the EPT params. The base struct is ~976
    // bytes; padding to 4096 keeps every array element on a fresh page so
    // ept::install_hook's "page-aligned" contract holds for all slots.
    struct alignas(4096) bp_params_storage_t {
        ept::ept_hook_install_params_t params;
        unsigned char _pad[4096 - sizeof(ept::ept_hook_install_params_t)];
    };
    static_assert(sizeof(bp_params_storage_t) == 4096, "bp_params_storage_t must be exactly one page");

    // Storage. All in this DLL's .data — no allocator, no syscalls at install.
    inline bp_params_storage_t g_bp_params[MAX_BPS] = {};
    inline bp_slot_t           g_bp_slots[MAX_BPS] = {};
    inline bp_event_t          g_bp_ring[RING_CAPACITY] = {};
    inline volatile long long  g_bp_ring_head = 0;

    // Wrapper table built via macro expansion — we need 64 distinct
    // function-pointer entries, one per template instantiation.
    typedef unsigned long long (__fastcall *bp_wrapper_fn)(ept::register_context_t*);

    // NOTE: We deliberately do NOT static-initialize this array with
    // { &bp_wrapper<0>, ... }. In a static initializer, function pointers
    // become absolute addresses in .data that require load-time base
    // relocations. Our manual mapper does not apply those, so the array
    // would hold the PREFERRED-base addresses (0x180...) even when the DLL
    // is loaded elsewhere — the stub would CALL into unmapped memory and
    // the process would die before the wrapper runs.
    // Populated at runtime by init_wrappers_once() instead; taking
    // &bp_wrapper<N> inside a function compiles to RIP-relative, which is
    // base-invariant.
    inline bp_wrapper_fn g_bp_wrappers[MAX_BPS] = {};

    inline void init_wrappers_once()
    {
        static volatile long initialized = 0;
        if (_InterlockedCompareExchange(&initialized, 1, 0) != 0) return;

        #define IBPW(N) g_bp_wrappers[(N)] = &bp_wrapper<(N)>
        #define IBPW_8(N) IBPW((N)+0); IBPW((N)+1); IBPW((N)+2); IBPW((N)+3); \
                         IBPW((N)+4); IBPW((N)+5); IBPW((N)+6); IBPW((N)+7)
        IBPW_8(0);  IBPW_8(8);  IBPW_8(16); IBPW_8(24);
        IBPW_8(32); IBPW_8(40); IBPW_8(48); IBPW_8(56);
        #undef IBPW_8
        #undef IBPW

        log::debugf(
            "[BP] wrappers init: [0]=%p [1]=%p [63]=%p (DLL-base-correct)\r\n",
            (void*)g_bp_wrappers[0], (void*)g_bp_wrappers[1],
            (void*)g_bp_wrappers[63]);
    }

    // Common logger — runs on the guest stack inside the EPT hook detour.
    // Keep it lean. Returns 0 → stub runs the original (relocated) bytes
    // and resumes the function. Nonzero → stub skips and returns directly
    // (don't use that here; we always want pass-through for sticky BPs).
    inline unsigned long long common_logger(ept::register_context_t* ctx, int bp_id)
    {
        if (bp_id < 0 || bp_id >= MAX_BPS) return 0;
        auto& slot = g_bp_slots[bp_id];

        // Disabled slots count nothing — minimum overhead.
        if (!slot.enabled) return 0;

        // Crash-survivable trace: if a subsequent access faults, the last
        // emitted [BP] line in zerohook.log tells us which BP fired last.
        // Written BEFORE any ring/stack work so a fault in those is visible.
        log::debugf(
            "[BP] hit id=%d target=%p rcx=%p rdx=%p rsp=%p\r\n",
            bp_id, (void*)slot.target_va, (void*)ctx->rcx,
            (void*)ctx->rdx, (void*)ctx->original_rsp);

        _InterlockedIncrement64(&slot.hits);

        if (slot.count_only) return 0;

        // Reserve a ring slot.
        const long long head = _InterlockedIncrement64(&g_bp_ring_head);
        const unsigned long long idx = (unsigned long long)(head - 1) & RING_MASK;
        bp_event_t& e = g_bp_ring[idx];

        e.tsc          = __rdtsc();
        e.target_va    = slot.target_va;
        e.original_rsp = ctx->original_rsp;
        e.rflags       = ctx->rflags;
        e.rax = ctx->rax; e.rcx = ctx->rcx; e.rdx = ctx->rdx; e.rbx = ctx->rbx;
        e.rbp = ctx->rbp; e.rsi = ctx->rsi; e.rdi = ctx->rdi;
        e.r8  = ctx->r8;  e.r9  = ctx->r9;  e.r10 = ctx->r10; e.r11 = ctx->r11;
        e.r12 = ctx->r12; e.r13 = ctx->r13; e.r14 = ctx->r14; e.r15 = ctx->r15;
        e.bp_id        = (unsigned short)bp_id;
        e.cpu_id       = 0xFFFF;  // not captured — would need GetCurrentProcessorNumber
        e.reserved     = 0;

        // Stack walk — top 4 return addresses from the saved RSP.
        const unsigned long long* sp = (const unsigned long long*)ctx->original_rsp;
        __try {
            e.stack[0] = sp[0];
            e.stack[1] = sp[1];
            e.stack[2] = sp[2];
            e.stack[3] = sp[3];
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            // Stack beyond mapping — leave whatever was there.
        }

        return 0;
    }

    // Find a free slot index, or -1 if all in use.
    inline int allocSlot()
    {
        for (int i = 0; i < MAX_BPS; i++) {
            if (!g_bp_slots[i].installed) return i;
        }
        return -1;
    }

    // Install an execute BP at target_va. Returns slot index (0..63) on
    // success — externally we expose this as id+1 so 0 reads as "fail".
    inline int install(unsigned long long target_va, bool count_only)
    {
        // One-shot: populate g_bp_wrappers with RIP-relative addresses so
        // they survive the manual mapper not applying base relocations.
        init_wrappers_once();

        if (target_va < 0x10000) {
            log::debugf(
                "[BP] install REJECT: target_va=%p < 0x10000\r\n",
                (void*)target_va);
            return -1;
        }

        int slot = allocSlot();
        if (slot < 0) {
            log::to_file("[BP] install REJECT: no free slot\r\n");
            return -1;
        }

        log::debugf(
            "[BP] install REQ slot=%d target=%p count_only=%d\r\n",
            slot, (void*)target_va, count_only ? 1 : 0);

        // Zero the params — install_hook fills it in from the relocator.
        bridge::memZero(&g_bp_params[slot].params, sizeof(ept::ept_hook_install_params_t));

        g_bp_slots[slot].installed = true;
        g_bp_slots[slot].count_only = count_only;
        g_bp_slots[slot].target_va = target_va;
        g_bp_slots[slot].hits = 0;
        g_bp_slots[slot].dropped = 0;
        // Enable AFTER install_hook returns so we don't race with a hit
        // that lands before the slot fields are coherent.
        g_bp_slots[slot].enabled = 0;

        char nameBuf[40];
        unsigned int hi = (unsigned int)(target_va >> 32);
        unsigned int lo = (unsigned int)(target_va & 0xFFFFFFFFu);
        // "BP[NN]@HHHHHHHH_LLLLLLLL"
        nameBuf[0]='B'; nameBuf[1]='P'; nameBuf[2]='[';
        nameBuf[3]='0' + (slot/10);
        nameBuf[4]='0' + (slot%10);
        nameBuf[5]=']'; nameBuf[6]='@';
        const char* digits = "0123456789ABCDEF";
        int p = 7;
        for (int i = 7; i >= 0; i--) nameBuf[p++] = digits[(hi >> (i*4)) & 0xF];
        nameBuf[p++] = '_';
        for (int i = 7; i >= 0; i--) nameBuf[p++] = digits[(lo >> (i*4)) & 0xF];
        nameBuf[p] = 0;

        bool ok = ept::install_hook(g_bp_params[slot].params,
                                    (unsigned char*)target_va,
                                    (void*)g_bp_wrappers[slot],
                                    nameBuf);
        if (!ok) {
            log::debugf(
                "[BP] install FAIL slot=%d target=%p\r\n",
                slot, (void*)target_va);
            g_bp_slots[slot].installed = false;
            g_bp_slots[slot].target_va = 0;
            return -1;
        }

        // Memory barrier so the slot fields land before enable flips on.
        _ReadWriteBarrier();
        _InterlockedExchange(&g_bp_slots[slot].enabled, 1);

        log::debugf(
            "[BP] install OK slot=%d target=%p wrapper=%p ENABLED\r\n",
            slot, (void*)target_va, (void*)g_bp_wrappers[slot]);

        return slot;
    }

    // Toggle without re-patching the EPT page. Cheap.
    inline bool setEnabled(int slot, bool enable)
    {
        if (slot < 0 || slot >= MAX_BPS) return false;
        if (!g_bp_slots[slot].installed) return false;
        _InterlockedExchange(&g_bp_slots[slot].enabled, enable ? 1 : 0);
        return true;
    }

    // Remove a BP — currently flips the enable bit and marks the slot free.
    // Full EPT-hook removal would need a hypervisor RPC (CMD_REMOVE_EPT_HOOK
    // if/when exposed). For now the patched page stays patched but the
    // wrapper short-circuits via !enabled — zero observable effect on game.
    inline bool remove(int slot)
    {
        if (slot < 0 || slot >= MAX_BPS) return false;
        if (!g_bp_slots[slot].installed) return false;
        _InterlockedExchange(&g_bp_slots[slot].enabled, 0);
        // Note: not reusing the slot until we have real EPT removal — the
        // shadow page is still in place and the wrapper still gets called.
        // Toggle-only removal is the safest middle ground.
        g_bp_slots[slot].installed = false;
        return true;
    }

    // Drain up to max_events from the ring tail. Reads g_bp_ring_head once,
    // copies events out, returns how many were copied. Caller is responsible
    // for tracking its own tail (we don't here — the pipe protocol exposes
    // a "snapshot from head-N" model: latest N events).
    inline unsigned long long drainLatest(bp_event_t* dest, unsigned long long max_events)
    {
        if (!dest || max_events == 0) return 0;
        if (max_events > RING_CAPACITY) max_events = RING_CAPACITY;

        const long long head = g_bp_ring_head;
        const unsigned long long avail = (head > 0)
            ? ((head < (long long)RING_CAPACITY) ? (unsigned long long)head : RING_CAPACITY)
            : 0;
        const unsigned long long n = (avail < max_events) ? avail : max_events;

        // Copy the most recent n events in chronological order.
        for (unsigned long long i = 0; i < n; i++) {
            const long long entry = head - (long long)n + (long long)i;
            const unsigned long long idx = (unsigned long long)entry & RING_MASK;
            dest[i] = g_bp_ring[idx];
        }
        return n;
    }

    inline void getStats(int slot, unsigned long long& hits, unsigned long long& dropped, bool& enabled)
    {
        if (slot < 0 || slot >= MAX_BPS) {
            hits = 0; dropped = 0; enabled = false; return;
        }
        hits    = (unsigned long long)g_bp_slots[slot].hits;
        dropped = (unsigned long long)g_bp_slots[slot].dropped;
        enabled = g_bp_slots[slot].enabled != 0;
    }

    // ── module-relative resolution ──────────────────────────────────────────

    inline unsigned long long resolveModuleVA(const char* moduleName, unsigned long long rva)
    {
        if (!moduleName || moduleName[0] == 0) return 0;
        void* base = peb::GetModuleBase(moduleName);
        if (!base) return 0;
        return (unsigned long long)base + rva;
    }

    // Heuristic: a hex-only string is treated as an absolute VA, anything
    // containing '.' or alpha (other than a-f) as a module name.
    inline bool looksLikeModuleName(const char* s)
    {
        for (int i = 0; s[i]; i++) {
            char c = s[i];
            if (c == '.') return true;
            // Letters g-z / G-Z aren't valid hex → must be a module name.
            if ((c >= 'g' && c <= 'z') || (c >= 'G' && c <= 'Z')) return true;
        }
        return false;
    }

    // ── pattern scan (AOB) ──────────────────────────────────────────────────
    //
    // Format: bytes separated by spaces, ?? = wildcard.
    //   "48 89 5C 24 ?? 57 48 83 EC 20"
    // Returns first matching VA in the given module, or 0 if none / unloaded.
    inline unsigned long long patternScan(const char* moduleName,
                                          const unsigned char* mask,
                                          const unsigned char* pattern,
                                          int patternLen)
    {
        if (!moduleName || patternLen <= 0) return 0;
        void* base = peb::GetModuleBase(moduleName);
        if (!base) return 0;

        // Extract module size from PE headers.
        IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
        IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((unsigned char*)base + dos->e_lfanew);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;
        unsigned int imgSize = nt->OptionalHeader.SizeOfImage;
        if (imgSize <= (unsigned int)patternLen) return 0;

        const unsigned char* hay = (const unsigned char*)base;
        const unsigned int end = imgSize - (unsigned int)patternLen;

        for (unsigned int i = 0; i <= end; i++) {
            __try {
                bool match = true;
                for (int j = 0; j < patternLen; j++) {
                    if (mask[j] && hay[i + j] != pattern[j]) { match = false; break; }
                }
                if (match) return (unsigned long long)(hay + i);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                // Page boundary — skip ahead one page.
                i = (i + 0x1000) & ~0xFFFu;
                if (i >= end) break;
            }
        }
        return 0;
    }

    // Variant: scan a raw VA range (no module resolution). Caller supplies
    // base + size. Same wildcard semantics as patternScan. Returns first
    // match VA or 0 if not found / unreadable.
    inline unsigned long long patternScanAddr(unsigned long long base,
                                              unsigned long long size,
                                              const unsigned char* mask,
                                              const unsigned char* pattern,
                                              int patternLen)
    {
        if (base < 0x10000 || patternLen <= 0) return 0;
        if (size <= (unsigned long long)patternLen) return 0;

        const unsigned char* hay = (const unsigned char*)base;
        const unsigned long long end = size - (unsigned long long)patternLen;

        for (unsigned long long i = 0; i <= end; i++) {
            __try {
                bool match = true;
                for (int j = 0; j < patternLen; j++) {
                    if (mask[j] && hay[i + j] != pattern[j]) { match = false; break; }
                }
                if (match) return (unsigned long long)(hay + i);
            } __except (EXCEPTION_EXECUTE_HANDLER) {
                i = (i + 0x1000) & ~0xFFFull;
                if (i >= end) break;
            }
        }
        return 0;
    }

    // Parse "48 89 ?? 24 ?? 57" into pattern[] and mask[] (mask=1 byte must
    // match, mask=0 wildcard). Returns parsed length, or -1 on parse error.
    inline int parsePattern(const char* str, int strLen,
                            unsigned char* pattern, unsigned char* mask, int maxLen)
    {
        int outIdx = 0;
        int i = 0;
        while (i < strLen && outIdx < maxLen) {
            // Skip whitespace
            while (i < strLen && (str[i] == ' ' || str[i] == '\t')) i++;
            if (i >= strLen) break;

            // Wildcard: ?, ??, *
            if (str[i] == '?' || str[i] == '*') {
                pattern[outIdx] = 0;
                mask[outIdx] = 0;
                outIdx++;
                i++;
                if (i < strLen && (str[i] == '?' || str[i] == '*')) i++;
                continue;
            }

            // Two hex chars.
            if (i + 1 >= strLen) return -1;
            int hi = bridge::hexVal(str[i]);
            int lo = bridge::hexVal(str[i + 1]);
            if (hi < 0 || lo < 0) return -1;
            pattern[outIdx] = (unsigned char)((hi << 4) | lo);
            mask[outIdx] = 1;
            outIdx++;
            i += 2;
        }
        return outIdx;
    }

} // namespace bridge_bp
