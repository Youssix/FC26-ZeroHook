#pragma once
#include <Windows.h>
#include "memory_ops.h"
#include "../comms/comms.h"   // canonical NTCLOSE_MAGIC, implant_request_t, ntclose_syscall

// NtClose-bridged watchpoint client. Sends requests via ntclose_syscall(magic,
// &request) — the kernel implant catches the magic handle, dispatches on
// req->command, and forwards to VMCALL 12..15 on the hypervisor.
//
// All canonical types (NTCLOSE_MAGIC, implant_request_t, ntclose_syscall) come
// from src/comms/comms.h — single source of truth shared with every other
// bridge user (ept_hook, dxgi_hooks, dda, competitive, division, game).
//
// Only watchpoint-specific extras live here: the four command IDs that extend
// comms.h's scheme, plus the install-request and event struct layouts. Those
// MUST stay byte-for-byte identical with the hypervisor project headers
// (shared/implant/implant_comms.h and shared/hypercall/watchpoint_request.h).

namespace bridge {

    // ── implant command IDs (extend the scheme in src/comms/comms.h) ────────
    constexpr unsigned int IMPLANT_CMD_INSTALL_WATCHPOINT   = 0x30;
    constexpr unsigned int IMPLANT_CMD_REMOVE_WATCHPOINT    = 0x31;
    constexpr unsigned int IMPLANT_CMD_DRAIN_WATCHPOINT_LOG = 0x32;
    constexpr unsigned int IMPLANT_CMD_GET_WATCHPOINT_STATS = 0x33;

    // ── access_mask bits (matches slat::hook::watchpoint_access_*) ──────────
    constexpr unsigned char WATCHPOINT_ACCESS_READ    = 1;
    constexpr unsigned char WATCHPOINT_ACCESS_WRITE   = 2;
    constexpr unsigned char WATCHPOINT_ACCESS_EXECUTE = 4;

    // Sentinel for filter_cr3: ~0ULL = follow cr3_tracker's target process.
    // 0 = no filter. Anything else = raw CR3 PFN to compare.
    constexpr unsigned long long WATCHPOINT_FILTER_TRACKER = ~0ULL;

    // Sentinel marker we stamp into req.status before the syscall. If the
    // implant ran, it overwrites this with 0 (success) or a small error code.
    // If the marker is still here after the call, the implant never saw us
    // (hypervisor not loaded, or magic handle changed on the implant side).
    constexpr unsigned int IMPLANT_STATUS_UNPROCESSED = 0xFEEDBEEF;

#pragma pack(push, 1)
    struct watchpoint_install_req_t {
        unsigned int       requested_id;     // 0 = auto-assign
        unsigned short     offset_in_page;   // 0..4095
        unsigned short     length_in_page;   // 1..4096
        unsigned char      access_mask;      // WATCHPOINT_ACCESS_* bits
        unsigned char      count_only;       // 0 = full event, 1 = counter-only
        unsigned char      reserved0[6];
        unsigned long long filter_cr3;       // 0 / WATCHPOINT_FILTER_TRACKER / raw
    };
    static_assert(sizeof(watchpoint_install_req_t) == 24, "watchpoint_install_req_t must be 24 bytes");

    // Mirrors watchpoint::event_t from the hypervisor (128 bytes). Drained
    // events get copied directly into the dest buffer we pass to the implant.
    struct watchpoint_event_t {
        unsigned long long tsc;
        unsigned long long rip;
        unsigned long long guest_cr3;
        unsigned long long operand_gva;
        unsigned long long operand_gpa;
        unsigned int       access_type;     // 0=R, 1=W, 2=X
        unsigned short     watchpoint_id;
        unsigned short     cpu_id;
        unsigned long long rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi;
        unsigned char      reserved[16];
    };
    static_assert(sizeof(watchpoint_event_t) == 128, "watchpoint_event_t must be 128 bytes");
#pragma pack(pop)

    // Returns true on a real implant round-trip; req->result has the meaningful
    // value. Returns false if the implant isn't loaded (status sentinel
    // survives the call).
    inline bool sendImplantRequest(implant_request_t* req)
    {
        req->status = IMPLANT_STATUS_UNPROCESSED;
        req->result = 0;

        ntclose_syscall(NTCLOSE_MAGIC, reinterpret_cast<unsigned long long>(req));

        return req->status != IMPLANT_STATUS_UNPROCESSED;
    }

    // ── Public-ish wrappers (used from protocol.h dispatcher) ──────────────

    // Returns assigned watchpoint id (1..1023) or 0 on failure.
    inline unsigned short watchInstall(uintptr_t target_va,
                                       unsigned char access_mask,
                                       unsigned short offset_in_page,
                                       unsigned short length_in_page,
                                       unsigned long long filter_cr3,
                                       unsigned char count_only)
    {
        watchpoint_install_req_t params = {};
        params.requested_id   = 0;  // auto-assign
        params.offset_in_page = offset_in_page;
        params.length_in_page = length_in_page;
        params.access_mask    = access_mask;
        params.count_only     = count_only;
        params.filter_cr3     = filter_cr3;

        implant_request_t req = {};
        req.command = IMPLANT_CMD_INSTALL_WATCHPOINT;
        req.param1  = target_va;
        req.param2  = reinterpret_cast<unsigned long long>(&params);

        if (!sendImplantRequest(&req)) return 0;
        return static_cast<unsigned short>(req.result);
    }

    // Returns 1 on success, 0 on failure.
    inline unsigned long long watchRemove(unsigned short id)
    {
        implant_request_t req = {};
        req.command = IMPLANT_CMD_REMOVE_WATCHPOINT;
        req.param1  = id;
        if (!sendImplantRequest(&req)) return 0;
        return req.result;
    }

    // Drains the caller CPU's ring into dest_buffer. Returns event count copied.
    inline unsigned long long watchDrain(watchpoint_event_t* dest_buffer,
                                         unsigned long long max_events)
    {
        if (!dest_buffer || max_events == 0) return 0;
        implant_request_t req = {};
        req.command = IMPLANT_CMD_DRAIN_WATCHPOINT_LOG;
        req.param1  = reinterpret_cast<unsigned long long>(dest_buffer);
        req.param2  = max_events;
        if (!sendImplantRequest(&req)) return 0;
        return req.result;
    }

    // Returns packed (hits << 32) | dropped, or 0 if implant unreachable.
    inline unsigned long long watchStats(unsigned short id)
    {
        implant_request_t req = {};
        req.command = IMPLANT_CMD_GET_WATCHPOINT_STATS;
        req.param1  = id;
        if (!sendImplantRequest(&req)) return 0;
        return req.result;
    }

} // namespace bridge
