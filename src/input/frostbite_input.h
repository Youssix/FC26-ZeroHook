#pragma once
#include <Windows.h>
#include <cstdint>
#include "../spoof/spoof_call.hpp"

// ============================================================================
// Frostbite InputReader — Zero Windows API Input System
//
// Reads keyboard, mouse, and scroll state directly from Frostbite's internal
// InputReader singleton. All calls go through the engine's vtable via spoof_call.
// No GetAsyncKeyState, no GetCursorPos, no WndProc dependency.
// ============================================================================

class FrostbiteInput {
public:
	static bool Init();
	static bool IsReady() { return s_ready; }

	static uint8_t VkToScanCode(int vKey) {
		if (vKey < 0 || vKey >= 256) return 0;
		return s_vkToScancode[vKey];
	}

	static void BlockGameInput(bool block);  // sets EPT hook blocking flag

	// ── Keyboard (scan code) ──────────────────────────────────────────
	static bool IsKeyDown(uint8_t scanCode) {
		if (!s_ready) return false;
		return spoof_call(s_fnIsKeyDown, s_reader, (uint32_t)scanCode) != 0;
	}
	static bool WasKeyPressed(uint8_t scanCode) {
		if (!s_ready) return false;
		return spoof_call(s_fnWasKeyPressed, s_reader, (uint32_t)scanCode) != 0;
	}
	static bool WasKeyReleased(uint8_t scanCode) {
		if (!s_ready) return false;
		return spoof_call(s_fnWasKeyReleased, s_reader, (uint32_t)scanCode) != 0;
	}

	// ── Keyboard (VK code helpers) ────────────────────────────────────
	static bool IsVKeyDown(int vKey) {
		if (!s_ready || vKey < 0 || vKey >= 256) return false;
		uint8_t sc = s_vkToScancode[vKey];
		return sc ? IsKeyDown(sc) : false;
	}
	static bool WasVKeyPressed(int vKey) {
		if (!s_ready || vKey < 0 || vKey >= 256) return false;
		uint8_t sc = s_vkToScancode[vKey];
		return sc ? WasKeyPressed(sc) : false;
	}
	static bool WasVKeyReleased(int vKey) {
		if (!s_ready || vKey < 0 || vKey >= 256) return false;
		uint8_t sc = s_vkToScancode[vKey];
		return sc ? WasKeyReleased(sc) : false;
	}

	// Drop-in replacement for GetAsyncKeyState
	static SHORT GetKeyState(int vKey) {
		return IsVKeyDown(vKey) ? (SHORT)0x8001 : 0;
	}

	// ── Mouse Buttons ─────────────────────────────────────────────────
	static bool IsMouseButtonDown(int button) {
		if (!s_ready || button < 0 || button > 4) return false;
		return spoof_call(s_fnIsMouseDown, s_reader, 0x3E8 + button) != 0;
	}
	static bool WasMouseButtonPressed(int button) {
		if (!s_ready || button < 0 || button > 4) return false;
		return spoof_call(s_fnWasMousePressed, s_reader, 0x3E8 + button) != 0;
	}
	static bool WasMouseButtonReleased(int button) {
		if (!s_ready || button < 0 || button > 4) return false;
		return spoof_call(s_fnWasMouseReleased, s_reader, 0x3E8 + button) != 0;
	}

	// ── Mouse Position & Deltas ───────────────────────────────────────
	static int GetMouseX()      { return s_ready ? spoof_call(s_fnGetMouseX, s_reader) : 0; }
	static int GetMouseY()      { return s_ready ? spoof_call(s_fnGetMouseY, s_reader) : 0; }
	static int GetMouseDeltaX() { return s_ready ? spoof_call(s_fnGetMouseDeltaX, s_reader) : 0; }
	static int GetMouseDeltaY() { return s_ready ? spoof_call(s_fnGetMouseDeltaY, s_reader) : 0; }
	static int GetMouseScroll() { return s_ready ? spoof_call(s_fnGetMouseScroll, s_reader) : 0; }

private:
	using fn_sc_t  = uint8_t(__fastcall*)(uintptr_t, uint32_t);
	using fn_btn_t = uint8_t(__fastcall*)(uintptr_t, int);
	using fn_int_t = int(__fastcall*)(uintptr_t);

	inline static uintptr_t s_reader = 0;
	inline static bool      s_ready = false;

	static constexpr uint8_t s_vkToScancode[256] = {
		0,0,0,0,0,0,0,0,
		0x0E,0x0F,0,0,0,0x1C,0,0,
		0x2A,0x1D,0x38,0,0x3A,0,0,0,
		0,0,0,0x01,0,0,0,0,
		0x39,0xC9,0xD1,0xCF,0xC7,0xCB,0xC8,0xCD,
		0xD0,0,0,0,0xB7,0xD2,0xD3,0,
		0x0B,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
		0x09,0x0A,0,0,0,0,0,0,
		0,0x1E,0x30,0x2E,0x20,0x12,0x21,0x22,
		0x23,0x17,0x24,0x25,0x26,0x32,0x31,0x18,
		0x19,0x10,0x13,0x1F,0x14,0x16,0x2F,0x11,
		0x2D,0x15,0x2C,0xDB,0xDC,0xDD,0,0,
		0x52,0x4F,0x50,0x51,0x4B,0x4C,0x4D,0x47,
		0x48,0x49,0x37,0x4E,0,0x4A,0x53,0xB5,
		0x3B,0x3C,0x3D,0x3E,0x3F,0x40,0x41,0x42,
		0x43,0x44,0x57,0x58,0,0,0,0,
		0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
		0x45,0x46,0,0,0,0,0,0,
		0,0,0,0,0,0,0,0,
		0x2A,0x36,0x1D,0x9D,0x38,0xB8,0,0,
		0,0,0,0,0,0,0,0,
		0,0,0,0,0,0,0,0,
		0,0,0x27,0x0D,0x33,0x0C,0x34,0x35,
		0x29,0,0,0,0,0,0,0,
		0,0,0,0,0,0,0,0,
		0,0,0,0,0,0,0,0,
		0,0,0,0x1A,0x2B,0x1B,0x28,0,
		0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
		0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	};

	inline static fn_sc_t  s_fnIsKeyDown        = nullptr;
	inline static fn_sc_t  s_fnWasKeyPressed     = nullptr;
	inline static fn_sc_t  s_fnWasKeyReleased    = nullptr;
	inline static fn_btn_t s_fnIsMouseDown       = nullptr;
	inline static fn_btn_t s_fnWasMousePressed   = nullptr;
	inline static fn_btn_t s_fnWasMouseReleased  = nullptr;
	inline static fn_int_t s_fnGetMouseX         = nullptr;
	inline static fn_int_t s_fnGetMouseY         = nullptr;
	inline static fn_int_t s_fnGetMouseDeltaX    = nullptr;
	inline static fn_int_t s_fnGetMouseDeltaY    = nullptr;
	inline static fn_int_t s_fnGetMouseScroll    = nullptr;

};
