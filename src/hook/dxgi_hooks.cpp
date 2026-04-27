#include "dxgi_hooks.h"
#include "reloc.h"
#include "../comms/comms.h"
#include "../offsets/offsets.h"
#include "../log/log.h"
#include "../log/fmt.h"
#include "../spoof/spoof_call.hpp"
#include "../menu/overlay.h"
#include "../renderer/renderer.h"
#include <dxgi1_4.h>
#include <d3d12.h>

namespace
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

    __declspec(align(4096)) ept_hook_install_params_t g_hookParams = {};

    constexpr int VTABLE_PRESENT        = 8;
    constexpr int VTABLE_RESIZE_BUFFERS = 13;
    constexpr UINT DEVICE_HEALTH_CHECK_INTERVAL = 128;
    constexpr UINT RESIZE_POLL_INTERVAL = 256;
    constexpr DWORD RESIZE_DRAIN_TIMEOUT_MS = 250;

    void patch_stub(unsigned char* stub, unsigned int size, unsigned long long detour_va)
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

    bool install_ept_hook(unsigned char* target, void* detour, const char* name)
    {
        char buf[256];

        if (g_debugLog) {
            fmt::snprintf(buf, sizeof(buf), "[ZeroHook] %s: %p\r\n", name, target);
            log::debug(buf);
        }

        // Follow JMP chain to resolve through inline hooks.
        // FC26 can point the vtable at a hot-patch thunk starting with
        // lea rsp,[rsp] (48 8D 24 24). Hooking there can corrupt adjacent
        // dense thunks on the shadow page, so skip it before resolving jumps.
        for (int chain = 0; chain < 8; chain++)
        {
            if (target[0] == 0x48 && target[1] == 0x8D && target[2] == 0x24 && target[3] == 0x24)
            {
                target += 4;
                continue;
            }
            if (target[0] == 0xE9)
            {
                int32_t rel = *(int32_t*)(target + 1);
                unsigned char* next = target + 5 + rel;
                if (g_debugLog) {
                    fmt::snprintf(buf, sizeof(buf), "[ZeroHook] %s: E9 chain %p -> %p\r\n", name, target, next);
                    log::debug(buf);
                }
                target = next;
            }
            else if (target[0] == 0xEB)
            {
                int8_t rel = *(int8_t*)(target + 1);
                unsigned char* next = target + 2 + rel;
                target = next;
            }
            else if (target[0] == 0xFF && target[1] == 0x25 && *(int32_t*)(target + 2) == 0)
            {
                unsigned char* next = *(unsigned char**)(target + 6);
                target = next;
            }
            else
                break;
        }

        if (g_debugLog) {
            fmt::snprintf(buf, sizeof(buf),
                "[ZeroHook] %s prologue: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X\r\n",
                name,
                target[0], target[1], target[2],  target[3],  target[4],
                target[5], target[6], target[7],  target[8],  target[9],
                target[10], target[11], target[12], target[13], target[14], target[15]);
            log::debug(buf);
        }

        auto reloc_result = reloc::relocate_displaced(target, (unsigned long long)target);
        if (!reloc_result.ok)
        {
            log::debug("[ZeroHook] FAIL: displaced byte relocation failed\r\n");
            return false;
        }

        for (unsigned int i = 0; i < STUB_SIZE; i++)
            g_hookParams.patched_stub[i] = STUB_TEMPLATE[i];
        patch_stub(g_hookParams.patched_stub, STUB_SIZE, (unsigned long long)detour);

        g_hookParams.stub_size = STUB_SIZE;
        g_hookParams.displaced_count = reloc_result.displaced_count;
        g_hookParams.relocated_size = reloc_result.size;
        g_hookParams.fixup_count = reloc_result.fixup_count;

        if (g_debugLog) {
            fmt::snprintf(buf, sizeof(buf),
                "[ZeroHook] %s reloc: target=%p detour=%p displaced=%u relocated=%u fixups=%u stub=%u\r\n",
                name, target, detour,
                reloc_result.displaced_count, reloc_result.size,
                reloc_result.fixup_count, STUB_SIZE);
            log::debug(buf);
        }

        for (unsigned int i = 0; i < reloc_result.size; i++)
            g_hookParams.relocated_bytes[i] = reloc_result.bytes[i];

        for (unsigned int i = 0; i < reloc_result.fixup_count; i++)
        {
            g_hookParams.fixups[i].offset_in_relocated = reloc_result.fixups[i].offset_in_relocated;
            g_hookParams.fixups[i].instr_len_after_disp = reloc_result.fixups[i].instr_len_after_disp;
            g_hookParams.fixups[i].abs_target = reloc_result.fixups[i].abs_target;
        }

        implant_request_t req = {};
        req.command = CMD_INSTALL_EPT_HOOK;
        req.param1 = (unsigned long long)target;
        req.param2 = (unsigned long long)&g_hookParams;

        ntclose_syscall(NTCLOSE_MAGIC, (unsigned long long)&req);

        if (g_debugLog) {
            fmt::snprintf(buf, sizeof(buf), "[ZeroHook] %s hook: status=%u, result=%llu\r\n",
                      name, req.status, req.result);
            log::debug(buf);
        }

        return req.status == 0 && req.result != 0;
    }

    // Same as install_ept_hook but returns the trampoline address (original function entry)
    // so the detour can call the original itself: oFn = (fn_t)trampoline; hr = oFn(args...);
    unsigned long long install_ept_hook_with_trampoline(unsigned char* target, void* detour, const char* name)
    {
        char buf[256];

        if (g_debugLog) {
            fmt::snprintf(buf, sizeof(buf), "[ZeroHook] %s: %p\r\n", name, target);
            log::debug(buf);
        }

        for (int chain = 0; chain < 8; chain++)
        {
            if (target[0] == 0x48 && target[1] == 0x8D && target[2] == 0x24 && target[3] == 0x24)
            {
                target += 4;
                continue;
            }
            if (target[0] == 0xE9)
            {
                int32_t rel = *(int32_t*)(target + 1);
                unsigned char* next = target + 5 + rel;
                if (g_debugLog) {
                    fmt::snprintf(buf, sizeof(buf), "[ZeroHook] %s: E9 chain %p -> %p\r\n", name, target, next);
                    log::debug(buf);
                }
                target = next;
            }
            else if (target[0] == 0xEB)
            {
                int8_t rel = *(int8_t*)(target + 1);
                unsigned char* next = target + 2 + rel;
                target = next;
            }
            else if (target[0] == 0xFF && target[1] == 0x25 && *(int32_t*)(target + 2) == 0)
            {
                unsigned char* next = *(unsigned char**)(target + 6);
                target = next;
            }
            else
                break;
        }

        if (g_debugLog) {
            fmt::snprintf(buf, sizeof(buf),
                "[ZeroHook] %s prologue: %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X %02X\r\n",
                name,
                target[0], target[1], target[2],  target[3],  target[4],
                target[5], target[6], target[7],  target[8],  target[9],
                target[10], target[11], target[12], target[13], target[14], target[15]);
            log::debug(buf);
        }

        auto reloc_result = reloc::relocate_displaced(target, (unsigned long long)target);
        if (!reloc_result.ok)
        {
            log::debug("[ZeroHook] FAIL: displaced byte relocation failed\r\n");
            return 0;
        }

        for (unsigned int i = 0; i < STUB_SIZE; i++)
            g_hookParams.patched_stub[i] = STUB_TEMPLATE[i];
        patch_stub(g_hookParams.patched_stub, STUB_SIZE, (unsigned long long)detour);

        g_hookParams.stub_size = STUB_SIZE;
        g_hookParams.displaced_count = reloc_result.displaced_count;
        g_hookParams.relocated_size = reloc_result.size;
        g_hookParams.fixup_count = reloc_result.fixup_count;

        if (g_debugLog) {
            fmt::snprintf(buf, sizeof(buf),
                "[ZeroHook] %s reloc: target=%p detour=%p displaced=%u relocated=%u fixups=%u stub=%u\r\n",
                name, target, detour,
                reloc_result.displaced_count, reloc_result.size,
                reloc_result.fixup_count, STUB_SIZE);
            log::debug(buf);
        }

        for (unsigned int i = 0; i < reloc_result.size; i++)
            g_hookParams.relocated_bytes[i] = reloc_result.bytes[i];

        for (unsigned int i = 0; i < reloc_result.fixup_count; i++)
        {
            g_hookParams.fixups[i].offset_in_relocated = reloc_result.fixups[i].offset_in_relocated;
            g_hookParams.fixups[i].instr_len_after_disp = reloc_result.fixups[i].instr_len_after_disp;
            g_hookParams.fixups[i].abs_target = reloc_result.fixups[i].abs_target;
        }

        implant_request_t req = {};
        req.command = CMD_INSTALL_EPT_HOOK;
        req.param1 = (unsigned long long)target;
        req.param2 = (unsigned long long)&g_hookParams;

        ntclose_syscall(NTCLOSE_MAGIC, (unsigned long long)&req);

        if (g_debugLog) {
            fmt::snprintf(buf, sizeof(buf), "[ZeroHook] %s hook: status=%u, trampoline=%p\r\n",
                      name, req.status, (void*)req.result);
            log::debug(buf);
        }

        return (req.status == 0) ? req.result : 0;
    }

    // ── D3D12 Renderer + Menu globals ──────────────────────────────────
    constexpr int MAX_BACK_BUFFERS = 8;

    struct FrameContext {
        ID3D12CommandAllocator* cmdAllocator;
        ID3D12Resource* backBuffer;
        D3D12_CPU_DESCRIPTOR_HANDLE rtvDescriptor;
        UINT64 fenceValue;
    };

    static CustomRenderer g_renderer;
    static bool g_rendererInitialized = false;
    static ID3D12Device* g_d3dDevice = nullptr;
    static ID3D12GraphicsCommandList* g_cmdList = nullptr;
    static ID3D12DescriptorHeap* g_rtvHeap = nullptr;
    static ID3D12Fence* g_fence = nullptr;
    static UINT64 g_fenceValue = 0;
    static FrameContext g_frameCtx[MAX_BACK_BUFFERS] = {};
    static UINT g_bufferCount = 0;
    static ID3D12CommandQueue* g_cmdQueue = nullptr;
    static UINT g_cachedWidth = 0;
    static UINT g_cachedHeight = 0;
    static HANDLE g_fenceEvent = nullptr;

    // Drain all GPU work queued before this point. ResizeBuffers is rare, so a
    // bounded wait here is acceptable; Present itself must never block.
    static bool DrainGpuWork()
    {
        if (!g_fence || !g_cmdQueue || !g_fenceEvent) return false;

        UINT64 waitVal = g_fenceValue;
        if (SpoofVCall<HRESULT>(g_cmdQueue, d3d12_vtable::CmdQueue::Signal,
                (ID3D12Fence*)g_fence, (UINT64)waitVal) != S_OK) return false;
        g_fenceValue++;

        if (SpoofVCall<UINT64>(g_fence, d3d12_vtable::Fence::GetCompletedValue) < waitVal) {
            if (SpoofVCall<HRESULT>(g_fence, d3d12_vtable::Fence::SetEventOnCompletion,
                    (UINT64)waitVal, (HANDLE)g_fenceEvent) != S_OK) return false;
            if (spoof_call(WaitForSingleObject,
                    (HANDLE)g_fenceEvent, (DWORD)RESIZE_DRAIN_TIMEOUT_MS) != WAIT_OBJECT_0) {
                return false;
            }
        }
        return true;
    }

    // ── Device health check (matches FC26 CheckDeviceAlive) ─────────
    // Fast path once g_d3dDevice is cached: skip the GetDevice/Release dance.
    static bool CheckDeviceAlive(IDXGISwapChain* sc)
    {
        if (g_rendererInitialized && g_d3dDevice) {
            HRESULT rr = SpoofVCall<HRESULT>(g_d3dDevice, d3d12_vtable::Device::GetDeviceRemovedReason);
            return SUCCEEDED(rr);
        }

        ID3D12Device* dev = nullptr;
        {
            const IID iid = __uuidof(ID3D12Device);
            void** vt = *reinterpret_cast<void***>(sc);
            using fn_t = HRESULT(*)(IDXGISwapChain*, const IID*, void**);
            HRESULT hr = spoof_call(reinterpret_cast<fn_t>(vt[dxgi_vtable::SwapChain::GetDevice]),
                sc, &iid, reinterpret_cast<void**>(&dev));
            if (FAILED(hr) || !dev) return false;
        }
        HRESULT rr = SpoofVCall<HRESULT>(dev, d3d12_vtable::Device::GetDeviceRemovedReason);
        SpoofVCall<ULONG>(dev, com_vtable::Release);
        return SUCCEEDED(rr);
    }

    // ── Lightweight: release only back buffer refs (for ResizeBuffers) ──
    static void ReleaseBackBuffersOnly()
    {
        for (UINT i = 0; i < g_bufferCount; i++) {
            if (g_frameCtx[i].backBuffer) {
                SpoofVCall<ULONG>(g_frameCtx[i].backBuffer, com_vtable::Release);
                g_frameCtx[i].backBuffer = nullptr;
            }
        }
    }

    // ── Re-acquire back buffers after ResizeBuffers (lightweight reinit) ──
    static bool ReinitBackBuffers(IDXGISwapChain* sc)
    {
        DXGI_SWAP_CHAIN_DESC scDesc = {};
        SpoofVCall<HRESULT>(sc, dxgi_vtable::SwapChain::GetDesc, &scDesc);
        g_bufferCount = scDesc.BufferCount;
        if (g_bufferCount < 3) g_bufferCount = 3;
        if (g_bufferCount > MAX_BACK_BUFFERS) g_bufferCount = MAX_BACK_BUFFERS;

        g_cachedWidth  = scDesc.BufferDesc.Width;
        g_cachedHeight = scDesc.BufferDesc.Height;

        // Recreate RTV heap for potentially different buffer count
        if (g_rtvHeap) { SpoofVCall<ULONG>(g_rtvHeap, com_vtable::Release); g_rtvHeap = nullptr; }
        {
            D3D12_DESCRIPTOR_HEAP_DESC rtvHeapDesc;
            rtvHeapDesc.Type = D3D12_DESCRIPTOR_HEAP_TYPE_RTV;
            rtvHeapDesc.NumDescriptors = g_bufferCount;
            rtvHeapDesc.Flags = D3D12_DESCRIPTOR_HEAP_FLAG_NONE;
            rtvHeapDesc.NodeMask = 1;
            const IID iid = __uuidof(ID3D12DescriptorHeap);
            void** vt = *reinterpret_cast<void***>(g_d3dDevice);
            using fn_t = HRESULT(*)(ID3D12Device*, const D3D12_DESCRIPTOR_HEAP_DESC*, const IID*, void**);
            HRESULT hr = spoof_call(reinterpret_cast<fn_t>(vt[d3d12_vtable::Device::CreateDescriptorHeap]),
                g_d3dDevice, (const D3D12_DESCRIPTOR_HEAP_DESC*)&rtvHeapDesc, &iid,
                reinterpret_cast<void**>(&g_rtvHeap));
            if (FAILED(hr) || !g_rtvHeap) return false;
        }

        // Re-acquire back buffers and create RTVs
        {
            void** vt = *reinterpret_cast<void***>(g_d3dDevice);
            using fn_t = UINT(*)(ID3D12Device*, D3D12_DESCRIPTOR_HEAP_TYPE);
            UINT rtvDescSize = spoof_call(reinterpret_cast<fn_t>(vt[d3d12_vtable::Device::GetDescriptorHandleIncrementSize]),
                g_d3dDevice, (D3D12_DESCRIPTOR_HEAP_TYPE)D3D12_DESCRIPTOR_HEAP_TYPE_RTV);

            D3D12_CPU_DESCRIPTOR_HANDLE rtvHandle = g_rtvHeap->GetCPUDescriptorHandleForHeapStart();

            for (UINT i = 0; i < g_bufferCount; i++) {
                ID3D12Resource* pBuf = nullptr;
                g_frameCtx[i].rtvDescriptor = rtvHandle;
                const IID iid = __uuidof(ID3D12Resource);
                void** scVt = *reinterpret_cast<void***>(sc);
                using gbfn = HRESULT(*)(IDXGISwapChain*, UINT, const IID*, void**);
                HRESULT hr = spoof_call(reinterpret_cast<gbfn>(scVt[dxgi_vtable::SwapChain::GetBuffer]),
                    sc, i, &iid, reinterpret_cast<void**>(&pBuf));
                if (FAILED(hr) || !pBuf) return false;

                SpoofVCall(g_d3dDevice, d3d12_vtable::Device::CreateRenderTargetView,
                    (ID3D12Resource*)pBuf, (const D3D12_RENDER_TARGET_VIEW_DESC*)nullptr,
                    (D3D12_CPU_DESCRIPTOR_HANDLE)rtvHandle);
                g_frameCtx[i].backBuffer = pBuf;
                g_frameCtx[i].fenceValue = 0;

                rtvHandle.ptr += rtvDescSize;
            }
        }

        log::debug("[Present] Back buffers re-acquired (lightweight reinit)\r\n");
        return true;
    }

    static volatile bool g_needsBackBufferReinit = false;

    // ── Teardown all D3D12 resources on device loss ──────────────────
    static void TeardownD3D12()
    {
        log::debug("[Present] TeardownD3D12 — device lost, releasing resources\r\n");

        g_renderer.Shutdown();

        if (g_cmdList)   { SpoofVCall<ULONG>(g_cmdList, com_vtable::Release); g_cmdList = nullptr; }
        for (UINT i = 0; i < g_bufferCount; i++) {
            if (g_frameCtx[i].cmdAllocator) {
                SpoofVCall<ULONG>(g_frameCtx[i].cmdAllocator, com_vtable::Release);
                g_frameCtx[i].cmdAllocator = nullptr;
            }
            if (g_frameCtx[i].backBuffer) {
                SpoofVCall<ULONG>(g_frameCtx[i].backBuffer, com_vtable::Release);
                g_frameCtx[i].backBuffer = nullptr;
            }
            g_frameCtx[i].fenceValue = 0;
        }
        if (g_rtvHeap)   { SpoofVCall<ULONG>(g_rtvHeap, com_vtable::Release); g_rtvHeap = nullptr; }
        if (g_fence)     { SpoofVCall<ULONG>(g_fence, com_vtable::Release); g_fence = nullptr; }
        if (g_fenceEvent){ spoof_call(CloseHandle, (HANDLE)g_fenceEvent); g_fenceEvent = nullptr; }
        if (g_d3dDevice) { SpoofVCall<ULONG>(g_d3dDevice, com_vtable::Release); g_d3dDevice = nullptr; }

        g_fenceValue = 0;
        g_bufferCount = 0;
        g_cmdQueue = nullptr;
        g_needsBackBufferReinit = false;
        g_rendererInitialized = false;
    }

    // CommandQueue offset varies by Windows build
    static uintptr_t get_cmdqueue_offset()
    {
        BYTE* pPeb = (BYTE*)__readgsqword(0x60);
        USHORT build = *(USHORT*)((uintptr_t)pPeb + 0x120);

        static bool logged = false;
        uintptr_t off;
        if (build == 19045 || build == 22621) off = 0x118;       // Win10 / Win11 22H2
        else if (build == 22631)              off = 0x168;       // Win11 23H2
        else if (build >= 26100)              off = 0x138;       // Win11 24H2+
        else                                  off = 0x138;       // default

        if (!logged) {
            logged = true;
            if (g_debugLog) {
                char b[128];
                fmt::snprintf(b, sizeof(b), "[Present] OS build=%u cmdQueue offset=0x%llX\r\n",
                    (unsigned)build, (unsigned long long)off);
                log::debug(b);
            }
        }
        return off;
    }
}

// ── Stub context — matches push order in ept_hook_stub.h ─────────
struct register_context_t
{
    unsigned long long original_rsp;
    unsigned long long rflags;
    unsigned long long r15, r14, r13, r12, r11, r10, r9, r8;
    unsigned long long rdi, rsi, rbp, rbx, rdx, rcx, rax;
};


// ===== Present detour =====

extern "C" unsigned long long HookedPresent(void* ctx, void* pSwapChain,
    unsigned int syncInterval, unsigned int flags)
{
    static UINT s_deviceHealthCountdown = DEVICE_HEALTH_CHECK_INTERVAL;
    static UINT s_resizePollCountdown = RESIZE_POLL_INTERVAL;

    // Once initialized, throttle device health checks. The hot path should not
    // do a device vcall every Present; reset/execute failures still handle
    // immediate device-loss cases below.
    if (g_rendererInitialized) {
        if (--s_deviceHealthCountdown == 0) {
            s_deviceHealthCountdown = DEVICE_HEALTH_CHECK_INTERVAL;
            if (!CheckDeviceAlive((IDXGISwapChain*)pSwapChain)) {
                TeardownD3D12();
                return 0;  // EPT stub runs original Present
            }
        }
    }

    // ── Resolve command queue BEFORE init (FC26 pattern) ──
    if (!g_cmdQueue) {
        uintptr_t scAddr = (uintptr_t)pSwapChain;
        uintptr_t queueOffset = get_cmdqueue_offset();
        g_cmdQueue = *(ID3D12CommandQueue**)(scAddr + queueOffset);
        if (!g_cmdQueue) return 0;
    }

    // ── First-call init: create D3D12 resources + overlay ────────────
    if (!g_rendererInitialized)
    {
        char _buf[256];
        IDXGISwapChain* sc = (IDXGISwapChain*)pSwapChain;

        if (g_debugLog) {
            fmt::snprintf(_buf, sizeof(_buf), "[Present] First call — SwapChain=%p\r\n", pSwapChain);
            log::debug(_buf);
        }

        HRESULT hr;
        {
            const IID iid = __uuidof(ID3D12Device);
            void** vt = *reinterpret_cast<void***>(sc);
            using fn_t = HRESULT(*)(IDXGISwapChain*, const IID*, void**);
            hr = spoof_call(reinterpret_cast<fn_t>(vt[dxgi_vtable::SwapChain::GetDevice]),
                sc, &iid, reinterpret_cast<void**>(&g_d3dDevice));
        }

        if (g_debugLog) {
            fmt::snprintf(_buf, sizeof(_buf), "[Present] GetDevice hr=0x%08X device=%p\r\n",
                (unsigned)hr, g_d3dDevice);
            log::debug(_buf);
        }

        if (SUCCEEDED(hr) && g_d3dDevice)
        {
            DXGI_SWAP_CHAIN_DESC scDesc = {};
            SpoofVCall<HRESULT>(sc, dxgi_vtable::SwapChain::GetDesc, &scDesc);
            g_bufferCount = scDesc.BufferCount;
            if (g_bufferCount < 3) g_bufferCount = 3;  // FC26: minimum 3 for high FPS
            if (g_bufferCount > MAX_BACK_BUFFERS) g_bufferCount = MAX_BACK_BUFFERS;

            if (g_debugLog) {
                fmt::snprintf(_buf, sizeof(_buf),
                    "[Present] GetDesc fmt=%u %ux%u buffers=%u\r\n",
                    (unsigned)scDesc.BufferDesc.Format,
                    (unsigned)scDesc.BufferDesc.Width, (unsigned)scDesc.BufferDesc.Height,
                    (unsigned)g_bufferCount);
                log::debug(_buf);
            }

            // ── Per-backbuffer command allocators (FC26: allocators first) ──
            for (UINT i = 0; i < g_bufferCount; i++) {
                const IID iid = __uuidof(ID3D12CommandAllocator);
                void** vt = *reinterpret_cast<void***>(g_d3dDevice);
                using fn_t = HRESULT(*)(ID3D12Device*, D3D12_COMMAND_LIST_TYPE, const IID*, void**);
                hr = spoof_call(reinterpret_cast<fn_t>(vt[d3d12_vtable::Device::CreateCommandAllocator]),
                    g_d3dDevice, D3D12_COMMAND_LIST_TYPE_DIRECT, &iid,
                    reinterpret_cast<void**>(&g_frameCtx[i].cmdAllocator));
                if (FAILED(hr) || !g_frameCtx[i].cmdAllocator) {
                    log::debug("[Present] FAIL: CreateCommandAllocator failed\r\n");
                    TeardownD3D12();
                    return 0;
                }
                g_frameCtx[i].fenceValue = 0;
            }
            log::debug("[Present] Per-backbuffer allocators created\r\n");

            // ── Single command list (FC26: cmdList after allocators) ──
            {
                const IID iid = __uuidof(ID3D12GraphicsCommandList);
                void** vt = *reinterpret_cast<void***>(g_d3dDevice);
                using fn_t = HRESULT(*)(ID3D12Device*, UINT, D3D12_COMMAND_LIST_TYPE,
                    ID3D12CommandAllocator*, ID3D12PipelineState*, const IID*, void**);
                hr = spoof_call(reinterpret_cast<fn_t>(vt[d3d12_vtable::Device::CreateCommandList]),
                    g_d3dDevice, (UINT)0, D3D12_COMMAND_LIST_TYPE_DIRECT,
                    g_frameCtx[0].cmdAllocator, (ID3D12PipelineState*)nullptr,
                    &iid, reinterpret_cast<void**>(&g_cmdList));
            }
            if (FAILED(hr) || !g_cmdList ||
                SpoofVCall<HRESULT>(g_cmdList, d3d12_vtable::CmdList::Close) != S_OK) {
                log::debug("[Present] FAIL: CreateCommandList or Close failed\r\n");
                TeardownD3D12();
                return 0;
            }
            log::debug("[Present] Command list created\r\n");

            // ── RTV descriptor heap (FC26: explicit NodeMask=1) ──
            {
                D3D12_DESCRIPTOR_HEAP_DESC rtvHeapDesc;
                rtvHeapDesc.Type = D3D12_DESCRIPTOR_HEAP_TYPE_RTV;
                rtvHeapDesc.NumDescriptors = g_bufferCount;
                rtvHeapDesc.Flags = D3D12_DESCRIPTOR_HEAP_FLAG_NONE;
                rtvHeapDesc.NodeMask = 1;
                const IID iid = __uuidof(ID3D12DescriptorHeap);
                void** vt = *reinterpret_cast<void***>(g_d3dDevice);
                using fn_t = HRESULT(*)(ID3D12Device*, const D3D12_DESCRIPTOR_HEAP_DESC*, const IID*, void**);
                hr = spoof_call(reinterpret_cast<fn_t>(vt[d3d12_vtable::Device::CreateDescriptorHeap]),
                    g_d3dDevice, (const D3D12_DESCRIPTOR_HEAP_DESC*)&rtvHeapDesc, &iid,
                    reinterpret_cast<void**>(&g_rtvHeap));
            }
            if (FAILED(hr) || !g_rtvHeap) {
                log::debug("[Present] FAIL: RTV heap creation failed\r\n");
                TeardownD3D12();
                return 0;
            }

            // Get RTV descriptor increment size + create per-backbuffer RTVs
            {
                void** vt = *reinterpret_cast<void***>(g_d3dDevice);
                using fn_t = UINT(*)(ID3D12Device*, D3D12_DESCRIPTOR_HEAP_TYPE);
                UINT rtvDescSize = spoof_call(reinterpret_cast<fn_t>(vt[d3d12_vtable::Device::GetDescriptorHandleIncrementSize]),
                    g_d3dDevice, (D3D12_DESCRIPTOR_HEAP_TYPE)D3D12_DESCRIPTOR_HEAP_TYPE_RTV);

                D3D12_CPU_DESCRIPTOR_HANDLE rtvHandle = g_rtvHeap->GetCPUDescriptorHandleForHeapStart();

                for (UINT i = 0; i < g_bufferCount; i++) {
                    ID3D12Resource* pBuf = nullptr;

                    g_frameCtx[i].rtvDescriptor = rtvHandle;
                    const IID iid = __uuidof(ID3D12Resource);
                    void** scVt = *reinterpret_cast<void***>(sc);
                    using gbfn = HRESULT(*)(IDXGISwapChain*, UINT, const IID*, void**);
                    hr = spoof_call(reinterpret_cast<gbfn>(scVt[dxgi_vtable::SwapChain::GetBuffer]),
                        sc, i, &iid, reinterpret_cast<void**>(&pBuf));
                    if (FAILED(hr) || !pBuf) {
                        log::debug("[Present] FAIL: GetBuffer failed\r\n");
                        TeardownD3D12();
                        return 0;
                    }

                    SpoofVCall(g_d3dDevice, d3d12_vtable::Device::CreateRenderTargetView,
                        (ID3D12Resource*)pBuf, (const D3D12_RENDER_TARGET_VIEW_DESC*)nullptr,
                        (D3D12_CPU_DESCRIPTOR_HANDLE)rtvHandle);
                    g_frameCtx[i].backBuffer = pBuf;

                    rtvHandle.ptr += rtvDescSize;
                }
            }
            if (g_debugLog) {
                fmt::snprintf(_buf, sizeof(_buf), "[Present] RTV heap created with %u descriptors\r\n", g_bufferCount);
                log::debug(_buf);
            }

            // ── Fence (FC26: fenceValue starts at 1) ──
            {
                const IID iid = __uuidof(ID3D12Fence);
                void** vt = *reinterpret_cast<void***>(g_d3dDevice);
                using fn_t = HRESULT(*)(ID3D12Device*, UINT64, D3D12_FENCE_FLAGS, const IID*, void**);
                hr = spoof_call(reinterpret_cast<fn_t>(vt[d3d12_vtable::Device::CreateFence]),
                    g_d3dDevice, (UINT64)0, D3D12_FENCE_FLAG_NONE, &iid, reinterpret_cast<void**>(&g_fence));
            }
            if (FAILED(hr) || !g_fence) {
                log::debug("[Present] FAIL: CreateFence failed\r\n");
                TeardownD3D12();
                return 0;
            }
            g_fenceValue = 1;

            // Persistent fence event — reused every frame and by ResizeBuffers
            // drain. Auto-reset, unsignalled. Closed only in TeardownD3D12.
            g_fenceEvent = spoof_call(CreateEventW,
                (LPSECURITY_ATTRIBUTES)nullptr, (BOOL)FALSE, (BOOL)FALSE, (LPCWSTR)nullptr);
            if (!g_fenceEvent) {
                log::debug("[Present] FAIL: CreateEventW (fence event) failed\r\n");
                TeardownD3D12();
                return 0;
            }

            // ── Renderer init (FC26: hardcoded DXGI_FORMAT_R8G8B8A8_UNORM) ──
            log::debug("[Present] Calling D3D12Renderer::Init...\r\n");
            if (!g_renderer.Init(g_d3dDevice, DXGI_FORMAT_R8G8B8A8_UNORM))
            {
                log::debug("[Present] FAIL: D3D12Renderer::Init returned false\r\n");
                TeardownD3D12();
                return 0;
            }
            log::debug("[Present] Renderer init OK\r\n");

            log::debug("[Present] Calling overlay::Init\r\n");
            overlay::Init(&g_renderer);

            g_rendererInitialized = true;
            log::debug("[Present] === INIT COMPLETE ===\r\n");
        }
        else
        {
            log::debug("[Present] FAIL: GetDevice failed or device is null\r\n");
        }
    }

    // ── Per-frame: D3D12 plumbing → overlay → submit ────────────────
    if (!g_rendererInitialized) return 0;

    // ── 25H2 fix: lightweight back buffer reinit after ResizeBuffers ──
    if (g_needsBackBufferReinit) {
        g_needsBackBufferReinit = false;
        if (!ReinitBackBuffers((IDXGISwapChain*)pSwapChain)) {
            log::debug("[Present] Lightweight reinit failed, full teardown\r\n");
            TeardownD3D12();
            return 0;
        }
        // Re-map vertex buffer — GPU driver may invalidate mapping after resize
        g_renderer.RemapVertexBuffer();
    }

    // ── Lazy resize: ResizeBuffers hook invalidates the cache. Keep a low-rate
    // safety poll for swapchain changes that bypass the hook.
    bool pollResize = false;
    if (g_cachedWidth == 0) {
        pollResize = true;
        s_resizePollCountdown = RESIZE_POLL_INTERVAL;
    } else if (--s_resizePollCountdown == 0) {
        pollResize = true;
        s_resizePollCountdown = RESIZE_POLL_INTERVAL;
    }

    if (pollResize) {
        DXGI_SWAP_CHAIN_DESC scd = {};
        SpoofVCall<HRESULT>((IDXGISwapChain*)pSwapChain, dxgi_vtable::SwapChain::GetDesc, &scd);
        UINT w = scd.BufferDesc.Width, h = scd.BufferDesc.Height;
        if (g_cachedWidth == 0) { g_cachedWidth = w; g_cachedHeight = h; }
        if (w != g_cachedWidth || h != g_cachedHeight) {
            if (g_debugLog) {
                char fb[128];
                fmt::snprintf(fb, sizeof(fb), "[Present] Resize detected %ux%u -> %ux%u, teardown\r\n",
                    (unsigned)g_cachedWidth, (unsigned)g_cachedHeight, (unsigned)w, (unsigned)h);
                log::debug(fb);
            }
            g_cachedWidth = w;
            g_cachedHeight = h;
            TeardownD3D12();
            return 0;  // re-init on next Present call
        }
    }

    overlay::PollHotkeys();

    if (!overlay::NeedsFrame())
        return 0;

    // Get current backbuffer index (FC26: direct call, no QI to SwapChain3)
    UINT bbIdx = SpoofVCall<UINT>((IDXGISwapChain*)pSwapChain, dxgi_vtable::SwapChain3::GetCurrentBackBufferIndex);
    if (bbIdx >= g_bufferCount) {
        if (g_debugLog) {
            char fb[128];
            fmt::snprintf(fb, sizeof(fb), "[Present] BAIL bbIdx=%u >= bufCount=%u\r\n",
                (unsigned)bbIdx, (unsigned)g_bufferCount);
            log::debug(fb);
        }
        return 0;
    }

    FrameContext& fc = g_frameCtx[bbIdx];
    if (!fc.backBuffer) return 0;

    // Do not block Present. If this backbuffer's previous overlay work is still
    // in flight, skip overlay for this frame and let the original Present run.
    // Blocking here is the classic 1 FPS failure mode when the fence stalls.
    if (g_fence && g_fenceEvent && fc.fenceValue != 0 &&
        SpoofVCall<UINT64>(g_fence, d3d12_vtable::Fence::GetCompletedValue) < fc.fenceValue) {
        return 0;
    }

    bool drawOverlay = false;
    if (g_cachedWidth != 0 && g_cachedHeight != 0) {
        const float screenW = (float)g_cachedWidth;
        const float screenH = (float)g_cachedHeight;

        g_renderer.BeginFrame(screenW, screenH);
        drawOverlay = overlay::Frame(screenW, screenH);
    }

    if (!drawOverlay)
        return 0;

    // Reset THIS frame's allocator + the shared command list only when we
    // actually have overlay work to submit. This is the hot-path FPS fix.
    HRESULT hr1 = SpoofVCall<HRESULT>(fc.cmdAllocator, d3d12_vtable::CmdAlloc::Reset);
    HRESULT hr2 = SpoofVCall<HRESULT>(g_cmdList, d3d12_vtable::CmdList::Reset,
        (ID3D12CommandAllocator*)fc.cmdAllocator, (ID3D12PipelineState*)nullptr);
    if (hr1 != 0 || hr2 != 0) {
        if (g_debugLog) {
            char fb[128];
            fmt::snprintf(fb, sizeof(fb), "[Present] RESET FAIL alloc=0x%08X list=0x%08X\r\n",
                (unsigned)hr1, (unsigned)hr2);
            log::debug(fb);
        }
        HRESULT rr = SpoofVCall<HRESULT>(g_d3dDevice, d3d12_vtable::Device::GetDeviceRemovedReason);
        if (rr != 0) {
            if (g_debugLog) {
                char fb2[128];
                fmt::snprintf(fb2, sizeof(fb2), "[Present] DEVICE REMOVED reason=0x%08X\r\n", (unsigned)rr);
                log::debug(fb2);
            }
            TeardownD3D12();
        }
        return 0;
    }

    // Barrier: PRESENT → RENDER_TARGET
    D3D12_RESOURCE_BARRIER barrier;
    barrier.Type = D3D12_RESOURCE_BARRIER_TYPE_TRANSITION;
    barrier.Flags = D3D12_RESOURCE_BARRIER_FLAG_NONE;
    barrier.Transition.pResource = fc.backBuffer;
    barrier.Transition.Subresource = D3D12_RESOURCE_BARRIER_ALL_SUBRESOURCES;
    barrier.Transition.StateBefore = D3D12_RESOURCE_STATE_PRESENT;
    barrier.Transition.StateAfter = D3D12_RESOURCE_STATE_RENDER_TARGET;
    SpoofVCall(g_cmdList, d3d12_vtable::CmdList::ResourceBarrier,
        (UINT)1, (const D3D12_RESOURCE_BARRIER*)&barrier);

    // Set render target from pre-created RTV descriptor
    SpoofVCall(g_cmdList, d3d12_vtable::CmdList::OMSetRenderTargets,
        (UINT)1, (const D3D12_CPU_DESCRIPTOR_HANDLE*)&fc.rtvDescriptor,
        (BOOL)FALSE, (const D3D12_CPU_DESCRIPTOR_HANDLE*)nullptr);

    g_renderer.Render(g_cmdList);

    // Barrier: RENDER_TARGET → PRESENT
    barrier.Transition.StateBefore = D3D12_RESOURCE_STATE_RENDER_TARGET;
    barrier.Transition.StateAfter = D3D12_RESOURCE_STATE_PRESENT;
    SpoofVCall(g_cmdList, d3d12_vtable::CmdList::ResourceBarrier,
        (UINT)1, (const D3D12_RESOURCE_BARRIER*)&barrier);

    // Close + execute
    HRESULT hrClose = SpoofVCall<HRESULT>(g_cmdList, d3d12_vtable::CmdList::Close);
    if (hrClose != 0) {
        if (g_debugLog) {
            char fb[128];
            fmt::snprintf(fb, sizeof(fb), "[Present] CLOSE FAIL hr=0x%08X\r\n",
                (unsigned)hrClose);
            log::debug(fb);
        }
        return 0;
    }
    SpoofVCall(g_cmdQueue, d3d12_vtable::CmdQueue::ExecuteCommandLists,
        (UINT)1, reinterpret_cast<ID3D12CommandList* const*>(&g_cmdList));

    // Signal fence for this frame
    fc.fenceValue = g_fenceValue;
    SpoofVCall<HRESULT>(g_cmdQueue, d3d12_vtable::CmdQueue::Signal,
        (ID3D12Fence*)g_fence, (UINT64)g_fenceValue);
    g_fenceValue++;

    return 0;
}

// ===== ResizeBuffers detour =====
// DXGI rejects ResizeBuffers with DXGI_ERROR_INVALID_CALL if any outstanding
// references to the back buffers (including implicit GPU references from
// in-flight command lists) still exist. We must:
//   1. Drain all GPU work on our queue (signal fence + wait on event) so the
//      GPU is done with the back buffers we rendered into last frame.
//   2. Release our ID3D12Resource* back-buffer references.
//   3. Return 0 so the original ResizeBuffers runs — now safe to destroy.
extern "C" unsigned long long HookedResizeBuffers(void* ctx, void* pSwapChain,
    unsigned int bufferCount, unsigned int width)
{
    if (g_rendererInitialized && g_d3dDevice) {
        log::debug("[ResizeBuffers] Draining GPU + releasing back buffers\r\n");
        if (DrainGpuWork()) {
            ReleaseBackBuffersOnly();
            g_needsBackBufferReinit = true;
        } else {
            log::debug("[ResizeBuffers] Drain timeout, full teardown\r\n");
            TeardownD3D12();
        }
    } else {
        log::debug("[ResizeBuffers] Full teardown\r\n");
        TeardownD3D12();
    }
    g_cachedWidth = 0;
    g_cachedHeight = 0;
    return 0;  // run original ResizeBuffers
}

// ===== Install DXGI hooks =====
void hook::install_dxgi_hooks()
{
    // All offsets already resolved by offsets::Init()
    if (!offsets::SwapChain)
    {
        log::debug("[ZeroHook] ERROR: SwapChain not resolved by offsets::Init()\r\n");
        return;
    }

    void** vtable = *(void***)offsets::SwapChain;

    overlay::SetMenuOnly(false);
    install_ept_hook(
        (unsigned char*)vtable[VTABLE_PRESENT],
        (void*)&HookedPresent,
        "Present");

    // ResizeBuffers hook — lightweight (just TeardownD3D12, no GPU sync).
    // Previous BSOD was from WaitForSingleObject(INFINITE) in the hook body.
    install_ept_hook(
        (unsigned char*)vtable[VTABLE_RESIZE_BUFFERS],
        (void*)&HookedResizeBuffers,
        "ResizeBuffers");

}
