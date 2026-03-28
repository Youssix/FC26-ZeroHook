#pragma once

class D3D12Renderer;

namespace overlay
{
    void Init(D3D12Renderer* renderer);
    void Frame(float screenW, float screenH);
    bool IsInitialized();
    inline bool s_tabSwitchFrame = false;  // true on the frame a tab switch happens
}
