#pragma once

class D3D12Renderer;

namespace overlay
{
    void SetMenuOnly(bool menuOnly);
    void Init(D3D12Renderer* renderer);
    bool Frame(float screenW, float screenH);
    bool IsInitialized();
}
