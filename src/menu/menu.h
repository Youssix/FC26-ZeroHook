#pragma once
#include <Windows.h>
#include "../input/frostbite_input.h"

// Simplified hotkey manager for no-CRT environment
// Uses fixed-size arrays instead of std::unordered_map/std::function

namespace menu
{
    inline bool isOpen = true;
    inline float menuOpacity = 1.0f;

    // ── Hotkey System ──────────────────────────────────────────────────
    struct HotkeyEntry {
        int vkCode;
        void(*action)();
        bool prevState;
        bool active;
    };

    constexpr int MAX_HOTKEYS = 32;
    inline HotkeyEntry hotkeys[MAX_HOTKEYS] = {};
    inline bool gIsBindingAnyHotkey = false;

    inline void RegisterHotkey(int vkCode, void(*action)())
    {
        for (int i = 0; i < MAX_HOTKEYS; i++)
        {
            if (!hotkeys[i].active)
            {
                hotkeys[i].vkCode = vkCode;
                hotkeys[i].action = action;
                hotkeys[i].prevState = FrostbiteInput::IsReady()
                    && FrostbiteInput::WasVKeyPressed(vkCode);
                hotkeys[i].active = true;
                return;
            }
        }
    }

    inline void UnregisterHotkey(int vkCode)
    {
        for (int i = 0; i < MAX_HOTKEYS; i++)
        {
            if (hotkeys[i].active && hotkeys[i].vkCode == vkCode)
            {
                hotkeys[i].active = false;
                return;
            }
        }
    }

    inline void CheckHotkeys()
    {
        if (gIsBindingAnyHotkey) return;

        for (int i = 0; i < MAX_HOTKEYS; i++)
        {
            if (!hotkeys[i].active) continue;

            bool isDown = FrostbiteInput::IsReady()
                ? FrostbiteInput::WasVKeyPressed(hotkeys[i].vkCode)
                : false;

            bool wasDown = hotkeys[i].prevState;

            if (isDown && !wasDown && hotkeys[i].action)
                hotkeys[i].action();

            hotkeys[i].prevState = isDown;
        }
    }

    inline bool BindHotkeyPoll(int& hotkey, bool& isBinding)
    {
        if (!isBinding) return false;

        for (int key = 1; key < 256; key++)
        {
            if (FrostbiteInput::IsReady() && FrostbiteInput::WasVKeyPressed(key))
            {
                hotkey = key;
                isBinding = false;
                gIsBindingAnyHotkey = false;
                return true;
            }
        }
        return false;
    }

    // ── Key Name Lookup ────────────────────────────────────────────────
    inline const char* GetKeyName(int vk)
    {
        switch (vk) {
        case VK_BACK:    return "Backspace";
        case VK_TAB:     return "Tab";
        case VK_RETURN:  return "Enter";
        case VK_SHIFT:   return "Shift";
        case VK_CONTROL: return "Ctrl";
        case VK_MENU:    return "Alt";
        case VK_ESCAPE:  return "Esc";
        case VK_SPACE:   return "Space";
        case VK_PRIOR:   return "PgUp";
        case VK_NEXT:    return "PgDn";
        case VK_END:     return "End";
        case VK_HOME:    return "Home";
        case VK_LEFT:    return "Left";
        case VK_UP:      return "Up";
        case VK_RIGHT:   return "Right";
        case VK_DOWN:    return "Down";
        case VK_INSERT:  return "Insert";
        case VK_DELETE:  return "Delete";
        case VK_F1:      return "F1";
        case VK_F2:      return "F2";
        case VK_F3:      return "F3";
        case VK_F4:      return "F4";
        case VK_F5:      return "F5";
        case VK_F6:      return "F6";
        case VK_F7:      return "F7";
        case VK_F8:      return "F8";
        case VK_F9:      return "F9";
        case VK_F10:     return "F10";
        case VK_F11:     return "F11";
        case VK_F12:     return "F12";
        default: break;
        }

        // A-Z
        if (vk >= 'A' && vk <= 'Z')
        {
            static char letter[2] = {};
            letter[0] = (char)vk;
            letter[1] = 0;
            return letter;
        }
        // 0-9
        if (vk >= '0' && vk <= '9')
        {
            static char digit[2] = {};
            digit[0] = (char)vk;
            digit[1] = 0;
            return digit;
        }

        return "?";
    }
}
