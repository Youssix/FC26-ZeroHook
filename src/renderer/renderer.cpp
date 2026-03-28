#include "renderer.h"
#include "../spoof/spoof_call.hpp"
#include "../peb/peb.h"
#include "../log/log.h"
#include "../log/fmt.h"
#include "generated_font.h"
#include <d3d12.h>

// sqrtf — compiler intrinsifies with /Oi
extern "C" float sqrtf(float);

namespace {
#include "shaders/vs.h"
#include "shaders/ps.h"
}

typedef HRESULT(WINAPI* PFN_D3D12_SERIALIZE_ROOT_SIGNATURE)(
	const D3D12_ROOT_SIGNATURE_DESC*,
	D3D_ROOT_SIGNATURE_VERSION,
	ID3DBlob**,
	ID3DBlob**);

namespace {
	constexpr int FONT_FIRST_CHAR   = GeneratedFont::FIRST_CHAR;
	constexpr int FONT_LAST_CHAR    = GeneratedFont::LAST_CHAR;
	constexpr int FONT_NUM_CHARS    = GeneratedFont::NUM_CHARS;
	constexpr int FONT_ATLAS_WIDTH  = GeneratedFont::ATLAS_WIDTH;
	constexpr int FONT_ATLAS_HEIGHT = GeneratedFont::ATLAS_HEIGHT;
}

void D3D12Renderer::CreateFontTexture() {
	log::to_file("[Renderer] CreateFontTexture START\r\n");

	static DWORD pixels[FONT_ATLAS_WIDTH * FONT_ATLAS_HEIGHT];
	for (int i = 0; i < FONT_ATLAS_WIDTH * FONT_ATLAS_HEIGHT; i++) {
		BYTE a = GeneratedFont::atlas[i];
		pixels[i] = a ? (((DWORD)a << 24) | 0x00FFFFFF) : 0;
	}
	pixels[0] = 0xFFFFFFFF;

	m_fontTexWidth  = (float)FONT_ATLAS_WIDTH;
	m_fontTexHeight = (float)FONT_ATLAS_HEIGHT;
	m_fontHeight    = GeneratedFont::FONT_HEIGHT;

	for (int i = 0; i < FONT_NUM_CHARS; i++) {
		m_glyphs[i].u0    = GeneratedFont::glyphs[i].u0;
		m_glyphs[i].v0    = GeneratedFont::glyphs[i].v0;
		m_glyphs[i].u1    = GeneratedFont::glyphs[i].u1;
		m_glyphs[i].v1    = GeneratedFont::glyphs[i].v1;
		m_glyphs[i].width = GeneratedFont::glyphs[i].width;
	}

	D3D12_HEAP_PROPERTIES heapProps = {};
	heapProps.Type = D3D12_HEAP_TYPE_DEFAULT;

	D3D12_RESOURCE_DESC texDesc = {};
	texDesc.Dimension          = D3D12_RESOURCE_DIMENSION_TEXTURE2D;
	texDesc.Width              = FONT_ATLAS_WIDTH;
	texDesc.Height             = FONT_ATLAS_HEIGHT;
	texDesc.DepthOrArraySize   = 1;
	texDesc.MipLevels          = 1;
	texDesc.Format             = DXGI_FORMAT_R8G8B8A8_UNORM;
	texDesc.SampleDesc.Count   = 1;
	texDesc.Layout             = D3D12_TEXTURE_LAYOUT_UNKNOWN;
	texDesc.Flags              = D3D12_RESOURCE_FLAG_NONE;

	HRESULT hr;
	{
		void** vt = *reinterpret_cast<void***>(m_device);
		const IID iid = __uuidof(ID3D12Resource);
		using fn_t = HRESULT(*)(ID3D12Device*, const D3D12_HEAP_PROPERTIES*, D3D12_HEAP_FLAGS,
			const D3D12_RESOURCE_DESC*, D3D12_RESOURCE_STATES,
			const D3D12_CLEAR_VALUE*, const IID*, void**);
		hr = spoof_call(reinterpret_cast<fn_t>(vt[d3d12_vtable::Device::CreateCommittedResource]),
			m_device, (const D3D12_HEAP_PROPERTIES*)&heapProps, D3D12_HEAP_FLAG_NONE,
			(const D3D12_RESOURCE_DESC*)&texDesc, D3D12_RESOURCE_STATE_COPY_DEST,
			(const D3D12_CLEAR_VALUE*)nullptr, &iid, reinterpret_cast<void**>(&m_fontTexture));
	}
	if (FAILED(hr)) {
		char buf[128];
		fmt::snprintf(buf, sizeof(buf), "[Renderer] Font texture failed: 0x%08X\r\n", (unsigned)hr);
		log::to_file(buf);
		return;
	}

	UINT64 uploadSize = 0;
	D3D12_PLACED_SUBRESOURCE_FOOTPRINT layout = {};
	{
		void** vt = *reinterpret_cast<void***>(m_device);
		using fn_t = void(*)(ID3D12Device*, const D3D12_RESOURCE_DESC*, UINT, UINT, UINT64,
			D3D12_PLACED_SUBRESOURCE_FOOTPRINT*, UINT*, UINT*, UINT64*);
		spoof_call(reinterpret_cast<fn_t>(vt[d3d12_vtable::Device::GetCopyableFootprints]),
			m_device, (const D3D12_RESOURCE_DESC*)&texDesc, (UINT)0, (UINT)1, (UINT64)0,
			&layout, (UINT*)nullptr, (UINT*)nullptr, &uploadSize);
	}

	D3D12_HEAP_PROPERTIES uploadHeapProps = {};
	uploadHeapProps.Type = D3D12_HEAP_TYPE_UPLOAD;

	D3D12_RESOURCE_DESC uploadDesc = {};
	uploadDesc.Dimension        = D3D12_RESOURCE_DIMENSION_BUFFER;
	uploadDesc.Width            = uploadSize;
	uploadDesc.Height           = 1;
	uploadDesc.DepthOrArraySize = 1;
	uploadDesc.MipLevels        = 1;
	uploadDesc.SampleDesc.Count = 1;
	uploadDesc.Layout           = D3D12_TEXTURE_LAYOUT_ROW_MAJOR;

	{
		void** vt = *reinterpret_cast<void***>(m_device);
		const IID iid = __uuidof(ID3D12Resource);
		using fn_t = HRESULT(*)(ID3D12Device*, const D3D12_HEAP_PROPERTIES*, D3D12_HEAP_FLAGS,
			const D3D12_RESOURCE_DESC*, D3D12_RESOURCE_STATES,
			const D3D12_CLEAR_VALUE*, const IID*, void**);
		hr = spoof_call(reinterpret_cast<fn_t>(vt[d3d12_vtable::Device::CreateCommittedResource]),
			m_device, (const D3D12_HEAP_PROPERTIES*)&uploadHeapProps, D3D12_HEAP_FLAG_NONE,
			(const D3D12_RESOURCE_DESC*)&uploadDesc, D3D12_RESOURCE_STATE_GENERIC_READ,
			(const D3D12_CLEAR_VALUE*)nullptr, &iid, reinterpret_cast<void**>(&m_fontUploadHeap));
	}
	if (FAILED(hr)) {
		char b2[128];
		fmt::snprintf(b2, sizeof(b2), "[Renderer] Font upload heap FAIL: 0x%08X\r\n", (unsigned)hr);
		log::to_file(b2);
		SpoofVCall<ULONG>(m_fontTexture, com_vtable::Release);
		m_fontTexture = nullptr;
		return;
	}
	{
		char b2[128];
		fmt::snprintf(b2, sizeof(b2), "[Renderer] Font upload heap=%p size=%llu\r\n",
			m_fontUploadHeap, (unsigned long long)uploadSize);
		log::to_file(b2);
	}

	void* mapped = nullptr;
	SpoofVCall<HRESULT>(m_fontUploadHeap, d3d12_vtable::Resource::Map,
		(UINT)0, (const D3D12_RANGE*)nullptr, &mapped);
	for (int row = 0; row < FONT_ATLAS_HEIGHT; row++) {
		safe_memcpy(
			(BYTE*)mapped + row * layout.Footprint.RowPitch,
			(BYTE*)pixels + row * FONT_ATLAS_WIDTH * 4,
			FONT_ATLAS_WIDTH * 4);
	}
	SpoofVCall(m_fontUploadHeap, d3d12_vtable::Resource::Unmap,
		(UINT)0, (const D3D12_RANGE*)nullptr);

	ID3D12CommandAllocator* cmdAlloc = nullptr;
	ID3D12GraphicsCommandList* cmdList = nullptr;
	ID3D12Fence* fence = nullptr;
	ID3D12CommandQueue* cmdQueue = nullptr;

	D3D12_COMMAND_QUEUE_DESC queueDesc = {};
	queueDesc.Type = D3D12_COMMAND_LIST_TYPE_DIRECT;
	queueDesc.Flags = D3D12_COMMAND_QUEUE_FLAG_NONE;
	queueDesc.NodeMask = 1;

	{
		void** vt = *reinterpret_cast<void***>(m_device);
		const IID iid = __uuidof(ID3D12CommandQueue);
		using fn_t = HRESULT(*)(ID3D12Device*, const D3D12_COMMAND_QUEUE_DESC*, const IID*, void**);
		hr = spoof_call(reinterpret_cast<fn_t>(vt[d3d12_vtable::Device::CreateCommandQueue]),
			m_device, (const D3D12_COMMAND_QUEUE_DESC*)&queueDesc, &iid, reinterpret_cast<void**>(&cmdQueue));
	}
	if (FAILED(hr)) { log::to_file("[Renderer] Font cmdQueue FAIL\r\n"); goto cleanup_texture; }
	log::to_file("[Renderer] Font cmdQueue created\r\n");

	{
		void** vt = *reinterpret_cast<void***>(m_device);
		const IID iid = __uuidof(ID3D12CommandAllocator);
		using fn_t = HRESULT(*)(ID3D12Device*, D3D12_COMMAND_LIST_TYPE, const IID*, void**);
		hr = spoof_call(reinterpret_cast<fn_t>(vt[d3d12_vtable::Device::CreateCommandAllocator]),
			m_device, D3D12_COMMAND_LIST_TYPE_DIRECT, &iid, reinterpret_cast<void**>(&cmdAlloc));
	}
	if (FAILED(hr)) { log::to_file("[Renderer] Font cmdAlloc FAIL\r\n"); SpoofVCall<ULONG>(cmdQueue, com_vtable::Release); goto cleanup_texture; }

	{
		void** vt = *reinterpret_cast<void***>(m_device);
		const IID iid = __uuidof(ID3D12GraphicsCommandList);
		using fn_t = HRESULT(*)(ID3D12Device*, UINT, D3D12_COMMAND_LIST_TYPE,
			ID3D12CommandAllocator*, ID3D12PipelineState*, const IID*, void**);
		hr = spoof_call(reinterpret_cast<fn_t>(vt[d3d12_vtable::Device::CreateCommandList]),
			m_device, (UINT)0, D3D12_COMMAND_LIST_TYPE_DIRECT,
			cmdAlloc, (ID3D12PipelineState*)nullptr,
			&iid, reinterpret_cast<void**>(&cmdList));
	}
	if (FAILED(hr)) { SpoofVCall<ULONG>(cmdAlloc, com_vtable::Release); SpoofVCall<ULONG>(cmdQueue, com_vtable::Release); goto cleanup_texture; }

	{
		void** vt = *reinterpret_cast<void***>(m_device);
		const IID iid = __uuidof(ID3D12Fence);
		using fn_t = HRESULT(*)(ID3D12Device*, UINT64, D3D12_FENCE_FLAGS, const IID*, void**);
		hr = spoof_call(reinterpret_cast<fn_t>(vt[d3d12_vtable::Device::CreateFence]),
			m_device, (UINT64)0, D3D12_FENCE_FLAG_NONE, &iid, reinterpret_cast<void**>(&fence));
	}
	if (FAILED(hr)) { log::to_file("[Renderer] Font fence FAIL\r\n"); SpoofVCall<ULONG>(cmdList, com_vtable::Release); SpoofVCall<ULONG>(cmdAlloc, com_vtable::Release); SpoofVCall<ULONG>(cmdQueue, com_vtable::Release); goto cleanup_texture; }
	log::to_file("[Renderer] Font copy resources ready — executing GPU upload\r\n");

	{
		D3D12_TEXTURE_COPY_LOCATION dst = {};
		dst.pResource = m_fontTexture;
		dst.Type = D3D12_TEXTURE_COPY_TYPE_SUBRESOURCE_INDEX;
		dst.SubresourceIndex = 0;

		D3D12_TEXTURE_COPY_LOCATION src = {};
		src.pResource = m_fontUploadHeap;
		src.Type = D3D12_TEXTURE_COPY_TYPE_PLACED_FOOTPRINT;
		src.PlacedFootprint = layout;

		{
			void** vt = *reinterpret_cast<void***>(cmdList);
			using fn_t = void(*)(ID3D12GraphicsCommandList*, const D3D12_TEXTURE_COPY_LOCATION*, UINT, UINT, UINT,
				const D3D12_TEXTURE_COPY_LOCATION*, const D3D12_BOX*);
			spoof_call(reinterpret_cast<fn_t>(vt[d3d12_vtable::CmdList::CopyTextureRegion]),
				cmdList, (const D3D12_TEXTURE_COPY_LOCATION*)&dst, (UINT)0, (UINT)0, (UINT)0,
				(const D3D12_TEXTURE_COPY_LOCATION*)&src, (const D3D12_BOX*)nullptr);
		}

		D3D12_RESOURCE_BARRIER barrier = {};
		barrier.Type = D3D12_RESOURCE_BARRIER_TYPE_TRANSITION;
		barrier.Transition.pResource = m_fontTexture;
		barrier.Transition.Subresource = D3D12_RESOURCE_BARRIER_ALL_SUBRESOURCES;
		barrier.Transition.StateBefore = D3D12_RESOURCE_STATE_COPY_DEST;
		barrier.Transition.StateAfter = D3D12_RESOURCE_STATE_PIXEL_SHADER_RESOURCE;
		SpoofVCall(cmdList, d3d12_vtable::CmdList::ResourceBarrier,
			(UINT)1, (const D3D12_RESOURCE_BARRIER*)&barrier);
	}

	SpoofVCall<HRESULT>(cmdList, d3d12_vtable::CmdList::Close);

	{
		ID3D12CommandList* ppCmdLists[] = { cmdList };
		SpoofVCall(cmdQueue, d3d12_vtable::CmdQueue::ExecuteCommandLists,
			(UINT)1, (ID3D12CommandList* const*)ppCmdLists);
		SpoofVCall<HRESULT>(cmdQueue, d3d12_vtable::CmdQueue::Signal,
			(ID3D12Fence*)fence, (UINT64)1);

		HANDLE event = spoof_call(CreateEventW,
			(LPSECURITY_ATTRIBUTES)nullptr, (BOOL)FALSE, (BOOL)FALSE, (LPCWSTR)nullptr);
		SpoofVCall<HRESULT>(fence, d3d12_vtable::Fence::SetEventOnCompletion,
			(UINT64)1, (HANDLE)event);
		spoof_call(WaitForSingleObject, (HANDLE)event, (DWORD)INFINITE);
		spoof_call(CloseHandle, (HANDLE)event);
	}
	log::to_file("[Renderer] Font GPU upload complete — fence signaled\r\n");

	SpoofVCall<ULONG>(fence, com_vtable::Release);
	SpoofVCall<ULONG>(cmdList, com_vtable::Release);
	SpoofVCall<ULONG>(cmdAlloc, com_vtable::Release);
	SpoofVCall<ULONG>(cmdQueue, com_vtable::Release);
	log::to_file("[Renderer] Font temp resources released\r\n");

	{
		D3D12_SHADER_RESOURCE_VIEW_DESC srvDesc = {};
		srvDesc.Format                        = DXGI_FORMAT_R8G8B8A8_UNORM;
		srvDesc.ViewDimension                 = D3D12_SRV_DIMENSION_TEXTURE2D;
		srvDesc.Shader4ComponentMapping       = D3D12_DEFAULT_SHADER_4_COMPONENT_MAPPING;
		srvDesc.Texture2D.MipLevels           = 1;
		{
			char b[256];
			fmt::snprintf(b, sizeof(b), "[Renderer] Creating SRV: tex=%p cpuHandle=%llX device=%p\r\n",
				m_fontTexture, (unsigned long long)m_fontSrvCpu.ptr, m_device);
			log::to_file(b);
		}
		SpoofVCall(m_device, d3d12_vtable::Device::CreateShaderResourceView,
			(ID3D12Resource*)m_fontTexture, (const D3D12_SHADER_RESOURCE_VIEW_DESC*)&srvDesc,
			(D3D12_CPU_DESCRIPTOR_HANDLE)m_fontSrvCpu);
	}

	log::to_file("[Renderer] Font atlas created OK\r\n");
	return;

cleanup_texture:
	SpoofVCall<ULONG>(m_fontTexture, com_vtable::Release);
	m_fontTexture = nullptr;
	if (m_fontUploadHeap) { SpoofVCall<ULONG>(m_fontUploadHeap, com_vtable::Release); m_fontUploadHeap = nullptr; }
}

bool D3D12Renderer::Init(ID3D12Device* dev, DXGI_FORMAT rtvFormat) {
	if (m_initialized) return true;
	if (!dev) return false;
	m_device = dev;

	char buf[256];
	fmt::snprintf(buf, sizeof(buf), "[Renderer] Init device=%p format=%u\r\n", dev, (unsigned)rtvFormat);
	log::to_file(buf);

	// SRV Descriptor Heap
	D3D12_DESCRIPTOR_HEAP_DESC heapDesc = {};
	heapDesc.Type           = D3D12_DESCRIPTOR_HEAP_TYPE_CBV_SRV_UAV;
	heapDesc.NumDescriptors = 1;
	heapDesc.Flags          = D3D12_DESCRIPTOR_HEAP_FLAG_SHADER_VISIBLE;
	heapDesc.NodeMask       = 1;

	HRESULT hr;
	{
		void** vt = *reinterpret_cast<void***>(m_device);
		const IID iid = __uuidof(ID3D12DescriptorHeap);
		using fn_t = HRESULT(*)(ID3D12Device*, const D3D12_DESCRIPTOR_HEAP_DESC*, const IID*, void**);
		hr = spoof_call(reinterpret_cast<fn_t>(vt[d3d12_vtable::Device::CreateDescriptorHeap]),
			m_device, (const D3D12_DESCRIPTOR_HEAP_DESC*)&heapDesc, &iid, reinterpret_cast<void**>(&m_srvHeap));
	}
	{
		char b[128];
		fmt::snprintf(b, sizeof(b), "[Renderer] SRV heap hr=0x%08X heap=%p\r\n", (unsigned)hr, m_srvHeap);
		log::to_file(b);
	}
	if (FAILED(hr)) return false;

	// Direct calls — trivial getters, not monitored by AC, and spoof_call
	// has ABI issues with struct-returning COM methods.
	m_fontSrvCpu = m_srvHeap->GetCPUDescriptorHandleForHeapStart();
	m_fontSrvGpu = m_srvHeap->GetGPUDescriptorHandleForHeapStart();
	{
		char b[128];
		fmt::snprintf(b, sizeof(b), "[Renderer] DescHandles cpu=%llX gpu=%llX\r\n",
			(unsigned long long)m_fontSrvCpu.ptr, (unsigned long long)m_fontSrvGpu.ptr);
		log::to_file(b);
	}

	// Root Signature
	D3D12_ROOT_PARAMETER rootParams[2] = {};
	rootParams[0].ParameterType             = D3D12_ROOT_PARAMETER_TYPE_32BIT_CONSTANTS;
	rootParams[0].Constants.Num32BitValues  = 16;
	rootParams[0].ShaderVisibility          = D3D12_SHADER_VISIBILITY_VERTEX;

	D3D12_DESCRIPTOR_RANGE srvRange = {};
	srvRange.RangeType          = D3D12_DESCRIPTOR_RANGE_TYPE_SRV;
	srvRange.NumDescriptors     = 1;
	rootParams[1].ParameterType                       = D3D12_ROOT_PARAMETER_TYPE_DESCRIPTOR_TABLE;
	rootParams[1].DescriptorTable.NumDescriptorRanges = 1;
	rootParams[1].DescriptorTable.pDescriptorRanges  = &srvRange;
	rootParams[1].ShaderVisibility                    = D3D12_SHADER_VISIBILITY_PIXEL;

	D3D12_STATIC_SAMPLER_DESC sampler = {};
	sampler.Filter           = D3D12_FILTER_MIN_MAG_MIP_LINEAR;
	sampler.AddressU         = D3D12_TEXTURE_ADDRESS_MODE_CLAMP;
	sampler.AddressV         = D3D12_TEXTURE_ADDRESS_MODE_CLAMP;
	sampler.AddressW         = D3D12_TEXTURE_ADDRESS_MODE_CLAMP;
	sampler.ComparisonFunc   = D3D12_COMPARISON_FUNC_ALWAYS;
	sampler.ShaderVisibility = D3D12_SHADER_VISIBILITY_PIXEL;

	D3D12_ROOT_SIGNATURE_DESC rsDesc = {};
	rsDesc.NumParameters     = 2;
	rsDesc.pParameters       = rootParams;
	rsDesc.NumStaticSamplers = 1;
	rsDesc.pStaticSamplers   = &sampler;
	rsDesc.Flags = D3D12_ROOT_SIGNATURE_FLAG_ALLOW_INPUT_ASSEMBLER_INPUT_LAYOUT |
	               D3D12_ROOT_SIGNATURE_FLAG_DENY_HULL_SHADER_ROOT_ACCESS |
	               D3D12_ROOT_SIGNATURE_FLAG_DENY_DOMAIN_SHADER_ROOT_ACCESS |
	               D3D12_ROOT_SIGNATURE_FLAG_DENY_GEOMETRY_SHADER_ROOT_ACCESS;

	HMODULE hD3D12 = (HMODULE)peb::GetModuleBase("d3d12.dll");
	if (!hD3D12) { log::to_file("[Renderer] FAIL: d3d12.dll not in PEB\r\n"); return false; }
	{
		char b[128];
		fmt::snprintf(b, sizeof(b), "[Renderer] d3d12.dll base=%p\r\n", hD3D12);
		log::to_file(b);
	}

	auto pfnSerialize = (PFN_D3D12_SERIALIZE_ROOT_SIGNATURE)
		peb::GetExportAddress(hD3D12, "D3D12SerializeRootSignature");
	if (!pfnSerialize) { log::to_file("[Renderer] FAIL: D3D12SerializeRootSignature export not found\r\n"); return false; }
	{
		char b[128];
		fmt::snprintf(b, sizeof(b), "[Renderer] SerializeRootSig=%p\r\n", pfnSerialize);
		log::to_file(b);
	}

	ID3DBlob* sigBlob = nullptr;
	ID3DBlob* errBlob = nullptr;
	hr = spoof_call(pfnSerialize, (const D3D12_ROOT_SIGNATURE_DESC*)&rsDesc,
		(D3D_ROOT_SIGNATURE_VERSION)D3D_ROOT_SIGNATURE_VERSION_1, (ID3DBlob**)&sigBlob, (ID3DBlob**)&errBlob);
	{
		char b[128];
		fmt::snprintf(b, sizeof(b), "[Renderer] SerializeRootSig hr=0x%08X blob=%p err=%p\r\n",
			(unsigned)hr, sigBlob, errBlob);
		log::to_file(b);
	}
	if (errBlob) SpoofVCall<ULONG>(errBlob, com_vtable::Release);
	if (FAILED(hr)) { if (sigBlob) SpoofVCall<ULONG>(sigBlob, com_vtable::Release); return false; }

	{
		void** blobVt = *reinterpret_cast<void***>(sigBlob);
		using fn_ptr_t = LPVOID(*)(ID3DBlob*);
		using fn_size_t = SIZE_T(*)(ID3DBlob*);
		LPVOID blobData = spoof_call(reinterpret_cast<fn_ptr_t>(blobVt[d3d12_vtable::Blob::GetBufferPointer]), sigBlob);
		SIZE_T blobSize = spoof_call(reinterpret_cast<fn_size_t>(blobVt[d3d12_vtable::Blob::GetBufferSize]), sigBlob);

		void** vt = *reinterpret_cast<void***>(m_device);
		const IID iid = __uuidof(ID3D12RootSignature);
		using fn_t = HRESULT(*)(ID3D12Device*, UINT, const void*, SIZE_T, const IID*, void**);
		hr = spoof_call(reinterpret_cast<fn_t>(vt[d3d12_vtable::Device::CreateRootSignature]),
			m_device, (UINT)0, (const void*)blobData, blobSize, &iid, reinterpret_cast<void**>(&m_rootSig));
	}
	SpoofVCall<ULONG>(sigBlob, com_vtable::Release);
	{
		char b[128];
		fmt::snprintf(b, sizeof(b), "[Renderer] CreateRootSig hr=0x%08X rootSig=%p\r\n", (unsigned)hr, m_rootSig);
		log::to_file(b);
	}
	if (FAILED(hr)) { Shutdown(); return false; }

	// PSO
	D3D12_INPUT_ELEMENT_DESC inputLayout[] = {
		{ "POSITION", 0, DXGI_FORMAT_R32G32_FLOAT,       0, 0,  D3D12_INPUT_CLASSIFICATION_PER_VERTEX_DATA, 0 },
		{ "TEXCOORD", 0, DXGI_FORMAT_R32G32_FLOAT,       0, 8,  D3D12_INPUT_CLASSIFICATION_PER_VERTEX_DATA, 0 },
		{ "COLOR",    0, DXGI_FORMAT_R32G32B32A32_FLOAT, 0, 16, D3D12_INPUT_CLASSIFICATION_PER_VERTEX_DATA, 0 },
	};

	D3D12_GRAPHICS_PIPELINE_STATE_DESC psoDesc;
	__stosb(reinterpret_cast<unsigned char*>(&psoDesc), 0, sizeof(psoDesc));
	psoDesc.NodeMask              = 1;
	psoDesc.PrimitiveTopologyType = D3D12_PRIMITIVE_TOPOLOGY_TYPE_TRIANGLE;
	psoDesc.pRootSignature        = m_rootSig;
	psoDesc.SampleMask            = UINT_MAX;
	psoDesc.NumRenderTargets      = 1;
	psoDesc.RTVFormats[0]         = rtvFormat;
	psoDesc.SampleDesc.Count      = 1;
	psoDesc.VS = { g_vsMain, sizeof(g_vsMain) };
	psoDesc.PS = { g_psMain, sizeof(g_psMain) };
	psoDesc.InputLayout = { inputLayout, _countof(inputLayout) };

	psoDesc.BlendState.RenderTarget[0].BlendEnable    = TRUE;
	psoDesc.BlendState.RenderTarget[0].SrcBlend       = D3D12_BLEND_SRC_ALPHA;
	psoDesc.BlendState.RenderTarget[0].DestBlend      = D3D12_BLEND_INV_SRC_ALPHA;
	psoDesc.BlendState.RenderTarget[0].BlendOp        = D3D12_BLEND_OP_ADD;
	psoDesc.BlendState.RenderTarget[0].SrcBlendAlpha  = D3D12_BLEND_ONE;
	psoDesc.BlendState.RenderTarget[0].DestBlendAlpha = D3D12_BLEND_INV_SRC_ALPHA;
	psoDesc.BlendState.RenderTarget[0].BlendOpAlpha   = D3D12_BLEND_OP_ADD;
	psoDesc.BlendState.RenderTarget[0].RenderTargetWriteMask = D3D12_COLOR_WRITE_ENABLE_ALL;

	psoDesc.RasterizerState.FillMode              = D3D12_FILL_MODE_SOLID;
	psoDesc.RasterizerState.CullMode              = D3D12_CULL_MODE_NONE;
	psoDesc.RasterizerState.DepthBias             = D3D12_DEFAULT_DEPTH_BIAS;
	psoDesc.RasterizerState.DepthBiasClamp        = D3D12_DEFAULT_DEPTH_BIAS_CLAMP;
	psoDesc.RasterizerState.SlopeScaledDepthBias  = D3D12_DEFAULT_SLOPE_SCALED_DEPTH_BIAS;
	psoDesc.RasterizerState.DepthClipEnable       = TRUE;

	psoDesc.DepthStencilState.DepthEnable    = FALSE;
	psoDesc.DepthStencilState.DepthWriteMask = D3D12_DEPTH_WRITE_MASK_ALL;
	psoDesc.DepthStencilState.DepthFunc      = D3D12_COMPARISON_FUNC_ALWAYS;
	psoDesc.DepthStencilState.FrontFace.StencilFailOp      = D3D12_STENCIL_OP_KEEP;
	psoDesc.DepthStencilState.FrontFace.StencilDepthFailOp = D3D12_STENCIL_OP_KEEP;
	psoDesc.DepthStencilState.FrontFace.StencilPassOp      = D3D12_STENCIL_OP_KEEP;
	psoDesc.DepthStencilState.FrontFace.StencilFunc        = D3D12_COMPARISON_FUNC_ALWAYS;
	psoDesc.DepthStencilState.BackFace = psoDesc.DepthStencilState.FrontFace;

	{
		void** vt = *reinterpret_cast<void***>(m_device);
		const IID iid = __uuidof(ID3D12PipelineState);
		using fn_t = HRESULT(*)(ID3D12Device*, const D3D12_GRAPHICS_PIPELINE_STATE_DESC*, const IID*, void**);
		hr = spoof_call(reinterpret_cast<fn_t>(vt[d3d12_vtable::Device::CreateGraphicsPipelineState]),
			m_device, (const D3D12_GRAPHICS_PIPELINE_STATE_DESC*)&psoDesc, &iid, reinterpret_cast<void**>(&m_pso));
	}
	{
		char b[128];
		fmt::snprintf(b, sizeof(b), "[Renderer] CreatePSO hr=0x%08X pso=%p\r\n", (unsigned)hr, m_pso);
		log::to_file(b);
	}
	if (FAILED(hr)) { Shutdown(); return false; }

	// Vertex Buffer
	UINT bufferSize = m_vertCapacity * sizeof(RdrVertex);
	D3D12_HEAP_PROPERTIES vbHeapProps = {};
	vbHeapProps.Type = D3D12_HEAP_TYPE_UPLOAD;

	D3D12_RESOURCE_DESC vbDesc = {};
	vbDesc.Dimension        = D3D12_RESOURCE_DIMENSION_BUFFER;
	vbDesc.Width            = bufferSize;
	vbDesc.Height           = 1;
	vbDesc.DepthOrArraySize = 1;
	vbDesc.MipLevels        = 1;
	vbDesc.SampleDesc.Count = 1;
	vbDesc.Layout           = D3D12_TEXTURE_LAYOUT_ROW_MAJOR;

	{
		void** vt = *reinterpret_cast<void***>(m_device);
		const IID iid = __uuidof(ID3D12Resource);
		using fn_t = HRESULT(*)(ID3D12Device*, const D3D12_HEAP_PROPERTIES*, D3D12_HEAP_FLAGS,
			const D3D12_RESOURCE_DESC*, D3D12_RESOURCE_STATES,
			const D3D12_CLEAR_VALUE*, const IID*, void**);
		hr = spoof_call(reinterpret_cast<fn_t>(vt[d3d12_vtable::Device::CreateCommittedResource]),
			m_device, (const D3D12_HEAP_PROPERTIES*)&vbHeapProps, D3D12_HEAP_FLAG_NONE,
			(const D3D12_RESOURCE_DESC*)&vbDesc, D3D12_RESOURCE_STATE_GENERIC_READ,
			(const D3D12_CLEAR_VALUE*)nullptr, &iid, reinterpret_cast<void**>(&m_vertexBuffer));
	}
	{
		char b[128];
		fmt::snprintf(b, sizeof(b), "[Renderer] VertexBuffer hr=0x%08X vb=%p size=%u\r\n",
			(unsigned)hr, m_vertexBuffer, (unsigned)bufferSize);
		log::to_file(b);
	}
	if (FAILED(hr)) { Shutdown(); return false; }

	D3D12_RANGE readRange = { 0, 0 };
	hr = SpoofVCall<HRESULT>(m_vertexBuffer, d3d12_vtable::Resource::Map,
		(UINT)0, (const D3D12_RANGE*)&readRange, (void**)&m_mappedVerts);
	{
		char b[128];
		fmt::snprintf(b, sizeof(b), "[Renderer] VB Map hr=0x%08X mapped=%p\r\n", (unsigned)hr, m_mappedVerts);
		log::to_file(b);
	}
	if (FAILED(hr)) { Shutdown(); return false; }

	CreateFontTexture();

	m_initialized = true;
	log::to_file("[Renderer] Init OK\r\n");
	return true;
}

void D3D12Renderer::BeginFrame(float width, float height) {
	if (!m_initialized) return;
	m_vertCount = 0;
	m_width = width;
	m_height = height;
	float L = 0, R = width, T = 0, B = height;
	m_proj[0]  = 2.0f / (R - L); m_proj[1]  = 0; m_proj[2]  = 0; m_proj[3]  = 0;
	m_proj[4]  = 0; m_proj[5]  = 2.0f / (T - B); m_proj[6]  = 0; m_proj[7]  = 0;
	m_proj[8]  = 0; m_proj[9]  = 0; m_proj[10] = 1; m_proj[11] = 0;
	m_proj[12] = (L+R)/(L-R); m_proj[13] = -(T+B)/(T-B); m_proj[14] = 0; m_proj[15] = 1;
}

void D3D12Renderer::AddVertex(float x, float y, float u, float v, float r, float g, float b, float a) {
	if (m_vertCount >= m_vertCapacity) return;
	RdrVertex& vtx = m_mappedVerts[m_vertCount++];
	vtx.x = x; vtx.y = y; vtx.u = u; vtx.v = v;
	vtx.r = r; vtx.g = g; vtx.b = b; vtx.a = a;
}

void D3D12Renderer::DrawRect(float x, float y, float w, float h, float r, float g, float b, float a) {
	if (!m_initialized || !m_mappedVerts || m_vertCount + 6 > m_vertCapacity) return;
	const float u = 0.5f / m_fontTexWidth, v = 0.5f / m_fontTexHeight;
	AddVertex(x, y, u, v, r, g, b, a);     AddVertex(x+w, y, u, v, r, g, b, a);   AddVertex(x+w, y+h, u, v, r, g, b, a);
	AddVertex(x, y, u, v, r, g, b, a);     AddVertex(x+w, y+h, u, v, r, g, b, a); AddVertex(x, y+h, u, v, r, g, b, a);
}

void D3D12Renderer::DrawRectOutline(float x, float y, float w, float h, float t, float r, float g, float b, float a) {
	DrawRect(x, y, w, t, r, g, b, a);
	DrawRect(x, y+h-t, w, t, r, g, b, a);
	DrawRect(x, y+t, t, h-t*2, r, g, b, a);
	DrawRect(x+w-t, y+t, t, h-t*2, r, g, b, a);
}

void D3D12Renderer::DrawTriangle(float x1, float y1, float x2, float y2, float x3, float y3, float r, float g, float b, float a) {
	if (!m_initialized || !m_mappedVerts || m_vertCount + 3 > m_vertCapacity) return;
	const float u = 0.5f / m_fontTexWidth, v = 0.5f / m_fontTexHeight;
	AddVertex(x1, y1, u, v, r, g, b, a); AddVertex(x2, y2, u, v, r, g, b, a); AddVertex(x3, y3, u, v, r, g, b, a);
}

void D3D12Renderer::DrawLine(float x1, float y1, float x2, float y2, float thickness, float r, float g, float b, float a) {
	if (!m_initialized || !m_mappedVerts || m_vertCount + 6 > m_vertCapacity) return;
	float dx = x2-x1, dy = y2-y1, len = sqrtf(dx*dx+dy*dy);
	if (len < 0.001f) return;
	float nx = -dy/len*thickness*0.5f, ny = dx/len*thickness*0.5f;
	const float u = 0.5f/m_fontTexWidth, v = 0.5f/m_fontTexHeight;
	AddVertex(x1+nx,y1+ny,u,v,r,g,b,a); AddVertex(x1-nx,y1-ny,u,v,r,g,b,a); AddVertex(x2-nx,y2-ny,u,v,r,g,b,a);
	AddVertex(x1+nx,y1+ny,u,v,r,g,b,a); AddVertex(x2-nx,y2-ny,u,v,r,g,b,a); AddVertex(x2+nx,y2+ny,u,v,r,g,b,a);
}

void D3D12Renderer::DrawText(float x, float y, const char* text, float r, float g, float b, float a, float scale) {
	if (!m_initialized || !m_mappedVerts || !m_fontTexture || !text) return;
	float curX = x, charH = m_fontHeight * scale;
	while (*text) {
		char c = *text++;
		if (c < FONT_FIRST_CHAR || c >= FONT_LAST_CHAR) { if (c == ' ') curX += m_glyphs[0].width * scale; continue; }
		int idx = c - FONT_FIRST_CHAR;
		const FontGlyph& gl = m_glyphs[idx];
		float charW = gl.width * scale;
		if (m_vertCount + 6 > m_vertCapacity) break;
		AddVertex(curX, y, gl.u0, gl.v0, r, g, b, a);       AddVertex(curX+charW, y, gl.u1, gl.v0, r, g, b, a);       AddVertex(curX+charW, y+charH, gl.u1, gl.v1, r, g, b, a);
		AddVertex(curX, y, gl.u0, gl.v0, r, g, b, a);       AddVertex(curX+charW, y+charH, gl.u1, gl.v1, r, g, b, a); AddVertex(curX, y+charH, gl.u0, gl.v1, r, g, b, a);
		curX += charW;
	}
}

float D3D12Renderer::MeasureText(const char* text, float scale) {
	if (!text) return 0;
	float width = 0;
	while (*text) {
		char c = *text++;
		if (c < FONT_FIRST_CHAR || c >= FONT_LAST_CHAR) { if (c == ' ') width += m_glyphs[0].width * scale; continue; }
		width += m_glyphs[c - FONT_FIRST_CHAR].width * scale;
	}
	return width;
}

void D3D12Renderer::Render(ID3D12GraphicsCommandList* cmdList) {
	if (!m_initialized || m_vertCount == 0) return;
	if (m_srvHeap)
		SpoofVCall(cmdList, d3d12_vtable::CmdList::SetDescriptorHeaps, (UINT)1, (ID3D12DescriptorHeap* const*)&m_srvHeap);
	SpoofVCall(cmdList, d3d12_vtable::CmdList::SetPipelineState, (ID3D12PipelineState*)m_pso);
	SpoofVCall(cmdList, d3d12_vtable::CmdList::SetGraphicsRootSignature, (ID3D12RootSignature*)m_rootSig);
	SpoofVCall(cmdList, d3d12_vtable::CmdList::SetGraphicsRoot32BitConstants, (UINT)0, (UINT)16, (const void*)m_proj, (UINT)0);
	if (m_fontTexture)
		SpoofVCall(cmdList, d3d12_vtable::CmdList::SetGraphicsRootDescriptorTable, (UINT)1, (D3D12_GPU_DESCRIPTOR_HANDLE)m_fontSrvGpu);
	SpoofVCall(cmdList, d3d12_vtable::CmdList::IASetPrimitiveTopology, (D3D12_PRIMITIVE_TOPOLOGY)D3D_PRIMITIVE_TOPOLOGY_TRIANGLELIST);
	D3D12_VERTEX_BUFFER_VIEW vbv = {};
	vbv.BufferLocation = SpoofVCall<D3D12_GPU_VIRTUAL_ADDRESS>(m_vertexBuffer, d3d12_vtable::Resource::GetGPUVirtualAddress);
	vbv.SizeInBytes    = m_vertCount * sizeof(RdrVertex);
	vbv.StrideInBytes  = sizeof(RdrVertex);
	SpoofVCall(cmdList, d3d12_vtable::CmdList::IASetVertexBuffers, (UINT)0, (UINT)1, (const D3D12_VERTEX_BUFFER_VIEW*)&vbv);
	D3D12_VIEWPORT vp = {}; vp.Width = m_width; vp.Height = m_height; vp.MaxDepth = 1.0f;
	SpoofVCall(cmdList, d3d12_vtable::CmdList::RSSetViewports, (UINT)1, (const D3D12_VIEWPORT*)&vp);
	D3D12_RECT scissor = { 0, 0, (LONG)m_width, (LONG)m_height };
	SpoofVCall(cmdList, d3d12_vtable::CmdList::RSSetScissorRects, (UINT)1, (const D3D12_RECT*)&scissor);
	SpoofVCall(cmdList, d3d12_vtable::CmdList::DrawInstanced, (UINT)m_vertCount, (UINT)1, (UINT)0, (UINT)0);
}

void D3D12Renderer::Shutdown() {
	if (m_vertexBuffer) {
		if (m_mappedVerts) { SpoofVCall(m_vertexBuffer, d3d12_vtable::Resource::Unmap, (UINT)0, (const D3D12_RANGE*)nullptr); m_mappedVerts = nullptr; }
		SpoofVCall<ULONG>(m_vertexBuffer, com_vtable::Release); m_vertexBuffer = nullptr;
	}
	if (m_fontTexture)    { SpoofVCall<ULONG>(m_fontTexture,    com_vtable::Release); m_fontTexture = nullptr; }
	if (m_fontUploadHeap) { SpoofVCall<ULONG>(m_fontUploadHeap, com_vtable::Release); m_fontUploadHeap = nullptr; }
	if (m_srvHeap)        { SpoofVCall<ULONG>(m_srvHeap,        com_vtable::Release); m_srvHeap = nullptr; }
	if (m_pso)            { SpoofVCall<ULONG>(m_pso,            com_vtable::Release); m_pso = nullptr; }
	if (m_rootSig)        { SpoofVCall<ULONG>(m_rootSig,        com_vtable::Release); m_rootSig = nullptr; }
	m_initialized = false;
}
