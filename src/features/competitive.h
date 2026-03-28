#pragma once

namespace competitive {
    inline bool unlockEnabled = false;
    inline bool initialized = false;
    bool Init(void* gameBase, unsigned long gameSize);
    bool IsReady();
    void SetEnabled(bool enable);
    bool IsEnabled();
}
