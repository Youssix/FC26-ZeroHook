#pragma once
#include "../renderer/renderer.h"

// ============================================================================
// Toast Notification System (NoCRT-safe, fixed buffers)
// ============================================================================

namespace toast
{
    enum class Type { Info, Warning, Error, Success };

    struct Entry {
        char    message[128];
        Type    type;
        float   elapsed;    // seconds since creation
        bool    active;
    };

    static constexpr int   MAX_TOASTS     = 8;
    static constexpr float FADE_IN        = 0.3f;
    static constexpr float DISPLAY        = 3.0f;
    static constexpr float FADE_OUT       = 1.0f;
    static constexpr float TOTAL_LIFE     = FADE_IN + DISPLAY + FADE_OUT;
    static constexpr float TOAST_W        = 320.0f;
    static constexpr float TOAST_H        = 44.0f;
    static constexpr float TOAST_GAP      = 6.0f;
    static constexpr float PADDING        = 14.0f;
    static constexpr float ACCENT_W       = 3.0f;

    inline Entry g_toasts[MAX_TOASTS] = {};

    // Master on/off switch — menu toggle "Show Notifications" binds to this.
    // Every toast::Show call honors it; no per-site gating needed.
    inline bool g_enabled = true;

    // ── Push a toast ──
    inline void Show(Type type, const char* msg)
    {
        if (!g_enabled) return;

        // Find a free slot, or overwrite the oldest
        int slot = -1;
        float oldest = 0;
        int oldestIdx = 0;

        for (int i = 0; i < MAX_TOASTS; i++) {
            if (!g_toasts[i].active) { slot = i; break; }
            if (g_toasts[i].elapsed > oldest) { oldest = g_toasts[i].elapsed; oldestIdx = i; }
        }
        if (slot < 0) slot = oldestIdx;

        Entry& e = g_toasts[slot];
        e.type = type;
        e.elapsed = 0;
        e.active = true;

        // Copy message (safe, no CRT)
        int i = 0;
        while (msg[i] && i < 126) { e.message[i] = msg[i]; i++; }
        e.message[i] = '\0';
    }

    // ── Tick + Render (call once per frame) ──
    inline void Render(D3D12Renderer& renderer, float screenW, float screenH, float dt)
    {
        // Count active toasts to stack from bottom
        int visCount = 0;

        for (int i = 0; i < MAX_TOASTS; i++) {
            Entry& e = g_toasts[i];
            if (!e.active) continue;

            e.elapsed += dt;
            if (e.elapsed > TOTAL_LIFE) { e.active = false; continue; }

            // Alpha: fade in → hold → fade out
            float alpha = 0.92f;
            if (e.elapsed < FADE_IN) {
                alpha = (e.elapsed / FADE_IN) * 0.92f;
            } else if (e.elapsed > FADE_IN + DISPLAY) {
                float t = (e.elapsed - FADE_IN - DISPLAY) / FADE_OUT;
                alpha = 0.92f * (1.0f - t);
            }
            if (alpha < 0.01f) continue;

            // Accent color by type
            float ar = 0.05f, ag = 0.65f, ab = 0.91f;  // Info = blue
            switch (e.type) {
            case Type::Warning: ar = 0.96f; ag = 0.62f; ab = 0.04f; break;
            case Type::Error:   ar = 0.94f; ag = 0.27f; ab = 0.27f; break;
            case Type::Success: ar = 0.06f; ag = 0.73f; ab = 0.51f; break;
            default: break;
            }

            float x = screenW - TOAST_W - PADDING;
            float y = screenH - PADDING - (TOAST_H + TOAST_GAP) * (visCount + 1);

            // Background
            renderer.DrawRect(x, y, TOAST_W, TOAST_H, 0.07f, 0.09f, 0.15f, alpha);
            // Left accent bar
            renderer.DrawRect(x, y, ACCENT_W, TOAST_H, ar, ag, ab, alpha);
            // Border
            renderer.DrawRectOutline(x, y, TOAST_W, TOAST_H, 1, 0.12f, 0.16f, 0.22f, alpha * 0.8f);
            // Text
            float fontH = renderer.GetFontHeight();
            float textY = y + (TOAST_H - fontH) / 2.0f;
            renderer.DrawText(x + ACCENT_W + 12, textY, e.message, 0.97f, 0.98f, 0.99f, alpha);

            visCount++;
        }
    }
}
