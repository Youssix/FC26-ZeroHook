#pragma once

namespace dda {
    inline bool bypassEnabled = false;
    inline bool initialized = false;
    bool Init(void* gameBase, unsigned long gameSize);
    bool IsReady();
    void SetEnabled(bool enable);
    bool IsEnabled();
}
