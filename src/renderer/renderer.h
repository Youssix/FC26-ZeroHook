#pragma once
#include <windows.h>
#include <d3d12.h>
struct RdrVertex {
	float x, y;
	float u, v;
	float r, g, b, a;
};

struct FontGlyph {
	float u0, v0, u1, v1;
	float width;
};

class D3D12Renderer {
public:
	bool  Init(ID3D12Device* dev, DXGI_FORMAT rtvFormat);
	void  BeginFrame(float width, float height);
	void  Render(ID3D12GraphicsCommandList* cmdList);

	void  Shutdown();
	bool  IsInitialized() const { return m_initialized; }

	void  DrawRect(float x, float y, float w, float h,
	               float r, float g, float b, float a);
	void  DrawRectOutline(float x, float y, float w, float h,
	                      float thickness, float r, float g, float b, float a);
	void  DrawTriangle(float x1, float y1, float x2, float y2, float x3, float y3,
	                   float r, float g, float b, float a);
	void  DrawLine(float x1, float y1, float x2, float y2,
	               float thickness, float r, float g, float b, float a);
	void  DrawText(float x, float y, const char* text,
	               float r, float g, float b, float a, float scale = 1.0f);
	float MeasureText(const char* text, float scale = 1.0f);
	float GetFontHeight() const { return m_fontHeight; }

private:
	void  CreateFontTexture();
	void  AddVertex(float x, float y, float u, float v, float r, float g, float b, float a);

	ID3D12Device*              m_device          = nullptr;
	ID3D12RootSignature*       m_rootSig         = nullptr;
	ID3D12PipelineState*       m_pso             = nullptr;
	ID3D12Resource*            m_vertexBuffer    = nullptr;
	ID3D12Resource*            m_fontTexture     = nullptr;
	ID3D12Resource*            m_fontUploadHeap  = nullptr;
	ID3D12DescriptorHeap*      m_srvHeap         = nullptr;
	D3D12_CPU_DESCRIPTOR_HANDLE m_fontSrvCpu     = {};
	D3D12_GPU_DESCRIPTOR_HANDLE m_fontSrvGpu     = {};

	RdrVertex*  m_mappedVerts  = nullptr;
	UINT        m_vertCount    = 0;
	UINT        m_vertCapacity = 16384;
	float       m_proj[16]     = {};
	float       m_width        = 0;
	float       m_height       = 0;
	bool        m_initialized  = false;

	FontGlyph   m_glyphs[96];
	float       m_fontHeight    = 16.0f;
	float       m_fontTexWidth  = 0;
	float       m_fontTexHeight = 0;
};

using CustomRenderer = D3D12Renderer;
