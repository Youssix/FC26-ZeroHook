#pragma once
#include <cstdint>

namespace division
{
    // Selected division index: 0=None, 1=DIV10 ... 10=DIV1, 11=ELITE500, 12=ELITE3000
    inline int selectedDivision = 0;

    // Active spoofed values (updated by UpdateValues when combo changes)
    inline unsigned int isElite        = 0x01;
    inline unsigned int srPoints       = 0x00000000;
    inline unsigned int progressionRank = 0x00000001;

    // Coop Rivals toggle
    inline bool enableCoopRivals = false;

    // State
    inline bool initialized = false;

    // Initialize: pattern scan for divspoofer vtable + coop rivals address
    bool Init(void* gameBase, unsigned long gameSize);
    bool IsReady();

    // Install EPT hook on the div spoofer vtable function
    bool InstallHook();
    bool IsHooked();

    // Update spoofed values based on selectedDivision index
    void UpdateValues(int divIndex);

    // Apply coop rivals byte patch (JZ -> JNZ)
    void SetCoopRivals(bool enable);
    bool IsCoopRivalsEnabled();

    // Legacy Apply (button press)
    void Apply();

    const char* GetDivisionName(int idx);
    int GetDivisionCount();
}
