#pragma once
#include <intrin.h>
#include "../offsets/offsets.h"

// IAT-safe memory copy - compiles to rep movsb (CPU instruction, no function call)
static __forceinline void safe_memcpy(void* dst, const void* src, unsigned long long size) {
	__movsb(static_cast<unsigned char*>(dst), static_cast<const unsigned char*>(src), size);
}

// Minimal enable_if (avoids <type_traits> dependency)
template<bool B, class T = void> struct spoof_enable_if {};
template<class T> struct spoof_enable_if<true, T> { using type = T; };
template<bool B, class T = void> using spoof_enable_if_t = typename spoof_enable_if<B, T>::type;

namespace detail
{
	extern "C" void* _spoofer_stub();

	template <typename Ret, typename... Args>
	static inline auto shellcode_stub_helper(
		const void* shell,
		Args... args
	) -> Ret
	{
		auto fn = (Ret(*)(Args...))(shell);
		return fn(args...);
	}

	template <size_t Argc, typename = void>
	struct argument_remapper
	{
		// 5+ params
		template<
			typename Ret,
			typename First,
			typename Second,
			typename Third,
			typename Fourth,
			typename... Pack
		>
		static auto do_call(
			const void* shell,
			void* shell_param,
			First first,
			Second second,
			Third third,
			Fourth fourth,
			Pack... pack
		) -> Ret
		{
			return shellcode_stub_helper<
				Ret,
				First,
				Second,
				Third,
				Fourth,
				void*,
				void*,
				Pack...
			>(
				shell,
				first,
				second,
				third,
				fourth,
				shell_param,
				nullptr,
				pack...
			);
		}
	};

	template <size_t Argc>
	struct argument_remapper<Argc, spoof_enable_if_t<(Argc <= 4)>>
	{
		// 4 or fewer params
		template<
			typename Ret,
			typename First = void*,
			typename Second = void*,
			typename Third = void*,
			typename Fourth = void*
		>
		static auto do_call(
			const void* shell,
			void* shell_param,
			First first = First{},
			Second second = Second{},
			Third third = Third{},
			Fourth fourth = Fourth{}
		) -> Ret
		{
			return shellcode_stub_helper<
				Ret,
				First,
				Second,
				Third,
				Fourth,
				void*,
				void*
			>(
				shell,
				first,
				second,
				third,
				fourth,
				shell_param,
				nullptr
			);
		}
	};
}


template <typename Ret, typename... Args>
static inline auto spoof_call(
	Ret(*fn)(Args...),
	Args... args
) -> Ret
{
	struct shell_params
	{
		const void* trampoline;
		void* function;
		void* rbx;
	};

	if (!offsets::SpoofLocation) {
		return fn(args...); // Fallback if SpoofLocation not set
	}

	shell_params p{ offsets::SpoofLocation, reinterpret_cast<void*>(fn) };
	using mapper = detail::argument_remapper<sizeof...(Args), void>;
	return mapper::template do_call<Ret, Args...>((const void*)&detail::_spoofer_stub, &p, args...);
}


// Spoofed VTable Call helper
template<typename Ret = void, typename Iface, typename... Args>
static inline Ret SpoofVCall(Iface* obj, unsigned int vIndex, Args... args) {
	void** vtable = *reinterpret_cast<void***>(obj);
	using fn_t = Ret(*)(Iface*, Args...);
	return spoof_call(reinterpret_cast<fn_t>(vtable[vIndex]), obj, args...);
}

// COM IUnknown VTable indices (shared by all COM objects)
namespace com_vtable {
	constexpr unsigned int QueryInterface = 0;
	constexpr unsigned int AddRef = 1;
	constexpr unsigned int Release = 2;
}

// DXGI VTable indices
namespace dxgi_vtable {
	namespace SwapChain {
		// IDXGIDeviceSubObject::GetDevice = 7
		constexpr unsigned int GetDevice = 7;
		constexpr unsigned int GetBuffer = 9;
		constexpr unsigned int GetDesc = 12;
	}
	namespace SwapChain3 {
		constexpr unsigned int GetCurrentBackBufferIndex = 36;
	}
}

// D3D12 VTable indices (verified from Windows SDK d3d12.h 10.0.26100.0)
namespace d3d12_vtable {
	namespace CmdList {
		constexpr unsigned int Close = 9;
		constexpr unsigned int Reset = 10;
		constexpr unsigned int DrawInstanced = 12;
		constexpr unsigned int DrawIndexedInstanced = 13;
		constexpr unsigned int CopyTextureRegion = 16;
		constexpr unsigned int IASetPrimitiveTopology = 20;
		constexpr unsigned int RSSetViewports = 21;
		constexpr unsigned int RSSetScissorRects = 22;
		constexpr unsigned int OMSetBlendFactor = 23;
		constexpr unsigned int SetPipelineState = 25;
		constexpr unsigned int ResourceBarrier = 26;
		constexpr unsigned int SetDescriptorHeaps = 28;
		constexpr unsigned int SetGraphicsRootSignature = 30;
		constexpr unsigned int SetGraphicsRootDescriptorTable = 32;
		constexpr unsigned int SetGraphicsRoot32BitConstants = 36;
		constexpr unsigned int IASetIndexBuffer = 43;
		constexpr unsigned int IASetVertexBuffers = 44;
		constexpr unsigned int OMSetRenderTargets = 46;
	}
	namespace CmdQueue {
		constexpr unsigned int ExecuteCommandLists = 10;
		constexpr unsigned int Signal = 14;
	}
	namespace Fence {
		constexpr unsigned int GetCompletedValue = 8;
		constexpr unsigned int SetEventOnCompletion = 9;
	}
	namespace CmdAlloc {
		constexpr unsigned int Reset = 8;
	}
	namespace Blob {
		constexpr unsigned int GetBufferPointer = 3;
		constexpr unsigned int GetBufferSize = 4;
	}
	namespace DescHeap {
		constexpr unsigned int GetCPUDescriptorHandleForHeapStart = 9;
		constexpr unsigned int GetGPUDescriptorHandleForHeapStart = 10;
	}
	namespace Device {
		constexpr unsigned int GetDeviceRemovedReason = 35;
		constexpr unsigned int GetDescriptorHandleIncrementSize = 15;
		constexpr unsigned int CreateCommandQueue = 8;
		constexpr unsigned int CreateCommandAllocator = 9;
		constexpr unsigned int CreateGraphicsPipelineState = 10;
		constexpr unsigned int CreateCommandList = 12;
		constexpr unsigned int CreateDescriptorHeap = 14;
		constexpr unsigned int CreateRootSignature = 16;
		constexpr unsigned int CreateShaderResourceView = 18;
		constexpr unsigned int CreateRenderTargetView = 20;
		constexpr unsigned int CreateCommittedResource = 27;
		constexpr unsigned int CreateFence = 36;
		constexpr unsigned int GetCopyableFootprints = 38;
	}
	namespace Resource {
		constexpr unsigned int Map = 8;
		constexpr unsigned int Unmap = 9;
		constexpr unsigned int GetDesc = 10;
		constexpr unsigned int GetGPUVirtualAddress = 11;
	}
}
