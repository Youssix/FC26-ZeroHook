#pragma once
#include "../renderer/renderer.h"
#ifndef NOCRT_BUILD
#include <vector>
#include <string>
#include <functional>
#endif

namespace CustomMenu {

// ============================================================================
// Color Definitions (matching modern_ui style)
// ============================================================================
struct Color {
	float r, g, b, a;
	Color() : r(1), g(1), b(1), a(1) {}
	Color(float _r, float _g, float _b, float _a = 1.0f) : r(_r), g(_g), b(_b), a(_a) {}
	Color WithAlpha(float newAlpha) const { return Color(r, g, b, newAlpha); }
};

namespace Colors {
	// ====== BLUELOCK Theme - Deep Navy + Electric Blue ======

	// Primary palette
	inline const Color Primary       = { 0.05f, 0.65f, 0.91f, 1.0f };  // Electric Blue #0EA5E9
	inline const Color PrimaryDark   = { 0.04f, 0.47f, 0.68f, 1.0f };  // Deep Blue #0B78AD
	inline const Color PrimaryGlow   = { 0.13f, 0.83f, 0.93f, 1.0f };  // Cyan Glow #22D3EE
	inline const Color Secondary     = { 0.94f, 0.27f, 0.27f, 1.0f };  // Red #EF4444
	inline const Color Success       = { 0.06f, 0.73f, 0.51f, 1.0f };  // Emerald #10B981
	inline const Color Warning       = { 0.96f, 0.62f, 0.04f, 1.0f };  // Amber #F59E0B
	inline const Color Accent        = { 0.13f, 0.83f, 0.93f, 1.0f };  // Cyan #22D3EE

	// Backgrounds - Deep Navy
	inline const Color Background    = { 0.04f, 0.055f, 0.10f, 0.98f }; // #0A0E1A
	inline const Color Surface       = { 0.07f, 0.09f, 0.15f, 1.0f };  // #111827
	inline const Color SurfaceHover  = { 0.12f, 0.16f, 0.22f, 1.0f };  // #1F2937
	inline const Color SurfaceActive = { 0.17f, 0.22f, 0.31f, 1.0f };  // #2C3850

	// Sidebar
	inline const Color Sidebar       = { 0.05f, 0.065f, 0.11f, 1.0f }; // Slightly darker than bg
	inline const Color SidebarHover  = { 0.08f, 0.11f, 0.18f, 1.0f };
	inline const Color SidebarActive = { 0.05f, 0.65f, 0.91f, 0.12f }; // Primary at 12% opacity

	// Text
	inline const Color Text          = { 0.97f, 0.98f, 0.99f, 1.0f };  // #F8FAFC
	inline const Color TextSecondary = { 0.58f, 0.64f, 0.72f, 1.0f };  // #94A3B8
	inline const Color TextDisabled  = { 0.28f, 0.33f, 0.42f, 1.0f };  // #475569

	// Borders
	inline const Color Border        = { 0.12f, 0.16f, 0.22f, 1.0f };  // #1E293B
	inline const Color BorderHover   = { 0.20f, 0.25f, 0.33f, 1.0f };  // #334155
}

// ============================================================================
// Input State
// ============================================================================
struct InputState {
	float mouseX = 0;
	float mouseY = 0;
	bool  mouseDown = false;
	bool  mouseClicked = false;   // true on frame when clicked
	bool  mouseReleased = false;  // true on frame when released
	float scrollDelta = 0;        // mouse wheel delta this frame

	void Update(float mx, float my, bool down, float scroll = 0) {
		mouseX = mx;
		mouseY = my;
		scrollDelta = scroll;
		// mouseDown still holds PREVIOUS frame's value here
		mouseClicked = down && !mouseDown;
		mouseReleased = !down && mouseDown;
		mouseDown = down;
	}

	bool IsInRect(float x, float y, float w, float h) const {
		return mouseX >= x && mouseX < x + w && mouseY >= y && mouseY < y + h;
	}
};

// ============================================================================
// Widget ID System (for tracking active/hot widgets)
// ============================================================================
using WidgetID = unsigned int;

inline WidgetID HashString(const char* str) {
	WidgetID hash = 5381;
	while (*str) {
		hash = ((hash << 5) + hash) + (unsigned char)(*str++);
	}
	return hash;
}

// ============================================================================
// Menu System
// ============================================================================
class Menu {
public:
	// Initialize menu
	void Init(D3D12Renderer* renderer);
	void Shutdown();

	// Per-frame update
	void BeginFrame(float screenW, float screenH, float mouseX, float mouseY, bool mouseDown, float scrollDelta = 0);
	void EndFrame();

	// Toggle menu visibility
	void Toggle() { m_isOpen = !m_isOpen; }
	bool IsOpen() const { return m_isOpen; }
	void SetOpen(bool open) { m_isOpen = open; }

	// Opacity (0.0 - 1.0)
	void SetOpacity(float o) { m_opacity = (o < 0.1f) ? 0.1f : (o > 1.0f ? 1.0f : o); }

	// Scroll input (call before BeginFrame with WM_MOUSEWHEEL delta)
	void SetScrollInput(float delta);

	// Check if menu wants mouse input
	bool WantsMouse() const;

	// ========== Layout Functions ==========
	void SetPosition(float x, float y) { m_windowX = x; m_windowY = y; }
	void SetSize(float w, float h) { m_windowW = w; m_windowH = h; }

	// ========== Window Functions ==========
	bool BeginWindow(const char* title, float minW = 800, float minH = 600);
	void EndWindow();

	// ========== Tab System ==========
	void BeginTabs();
	bool Tab(const char* label, int index);
	void TabDisabled(const char* label, int index);  // Grayed-out non-clickable tab
	void EndTabs();
	int  GetSelectedTab() const { return m_selectedTab; }
	void SetSelectedTab(int tab) { m_selectedTab = tab; }

	// ========== Section (collapsible group) ==========
	bool BeginSection(const char* title);
	void EndSection();

	// ========== Widgets ==========
	// Toggle returns true if value changed
	bool Toggle(const char* label, bool* value, const char* tooltip = nullptr);

	// Slider returns true if value changed
	bool SliderFloat(const char* label, float* value, float minVal, float maxVal,
	                 const char* format = "%.1f", const char* tooltip = nullptr);
	bool SliderInt(const char* label, int* value, int minVal, int maxVal,
	               const char* tooltip = nullptr);

	// Button returns true if clicked
	bool Button(const char* label, float width = -1, float height = 30);
	bool ButtonColored(const char* label, const Color& color, float width = -1, float height = 30);

	// Combo/Dropdown returns true if selection changed
	bool Combo(const char* label, int* currentIndex, const char** items, int itemCount);

	// Label (non-interactive)
	void Label(const char* text, const Color& color = Colors::Text);
	void LabelValue(const char* label, const char* value);

	// Spacing/Separator
	void Spacing(float pixels = 8);
	void Separator();

	// Text input
	bool InputText(const char* label, char* buffer, int bufferSize);

	// Status indicator (green/red dot with text)
	void StatusIndicator(const char* label, bool active, const char* tooltip = nullptr);

	// Row layout helpers
	void BeginRow(int columns = 2);
	void NextColumn();
	void EndRow();

	// Place next widget on the same line as previous, offset to the right
	void SameLine(float offset) {
		m_cursorY -= WIDGET_HEIGHT;
		m_contentX += offset;
		m_contentW -= offset;
	}

	// Restore content area after a SameLine widget
	void EndSameLine(float offset) {
		m_contentX -= offset;
		m_contentW += offset;
	}

	// Tooltip (call after widget)
	void SetTooltip(const char* text);

	// ========== Floating Window (for overlays like opponent info) ==========
	bool BeginFloatingWindow(const char* title, float defaultX, float defaultY, float defaultW, float defaultH, bool* open);
	void EndFloatingWindow();

private:
	// Drawing helpers
	void DrawRect(float x, float y, float w, float h, const Color& c);
	void DrawRectOutline(float x, float y, float w, float h, float thickness, const Color& c);
	void DrawText(float x, float y, const char* text, const Color& c, float scale = 1.0f);
	float MeasureText(const char* text, float scale = 1.0f);
	void DrawCircle(float cx, float cy, float radius, const Color& c, int segments = 16);
	void DrawTriangle(float x1, float y1, float x2, float y2, float x3, float y3, const Color& c);

	// Widget ID tracking
	WidgetID GetID(const char* label);
	bool IsHot(WidgetID id) const { return m_hotWidget == id; }
	bool IsActive(WidgetID id) const { return m_activeWidget == id; }
	void SetHot(WidgetID id) { m_hotWidget = id; }
	void SetActive(WidgetID id) { m_activeWidget = id; }
	void ClearActive() { m_activeWidget = 0; }

	// Clipping (returns true if widget at y with height h overlaps visible content)
	bool IsWidgetVisible(float y, float h) const;

	// Layout state
	float GetNextY() const { return m_cursorY; }
	void AdvanceCursor(float h);
	float GetContentWidth() const;
	float GetContentX() const { return m_contentX; }

	// Core state
	D3D12Renderer* m_renderer = nullptr;
	bool            m_isOpen = false;
	float           m_screenW = 0;
	float           m_screenH = 0;
	float           m_opacity = 1.0f;
	InputState      m_input;

	// Scroll state
	float m_scrollY = 0;
	float m_clipTop = 0;
	float m_clipBottom = 99999;

	// Window state
	float m_windowX = 50;
	float m_windowY = 50;
	float m_windowW = 900;
	float m_windowH = 650;
	bool  m_dragging = false;
	float m_dragOffsetX = 0;
	float m_dragOffsetY = 0;

	// Content area
	float m_contentX = 0;
	float m_contentY = 0;
	float m_contentW = 0;
	float m_contentH = 0;
	float m_cursorY = 0;

	// Widget tracking
	WidgetID m_hotWidget = 0;
	WidgetID m_activeWidget = 0;
	WidgetID m_idStack[16];
	int      m_idStackSize = 0;

	// Tab state
	int   m_selectedTab = 0;
	int   m_tabCount = 0;
	float m_tabY = 0;

	// Section state
	bool  m_inSection = false;
	float m_sectionIndent = 15;

	// Row state
	int   m_rowColumns = 1;
	int   m_currentColumn = 0;
	float m_rowStartY = 0;
	float m_rowMaxH = 0;
	float m_columnWidth = 0;

	// Combo popup state (drawn in EndFrame for z-order)
	bool      m_comboOpen = false;
	WidgetID  m_openComboID = 0;
	float     m_comboX = 0, m_comboY = 0, m_comboW = 0;
	const char** m_comboItems = nullptr;
	int       m_comboItemCount = 0;
	int*      m_comboValue = nullptr;
	int       m_comboScrollOffset = 0;
	bool      m_comboChanged = false;
	bool      m_comboClickSaved = false;
	static constexpr int COMBO_MAX_VISIBLE = 8;

	// Tooltip
	const char* m_tooltipText = nullptr;
	float       m_tooltipX = 0;
	float       m_tooltipY = 0;

	// Floating window state
	float m_floatX = 800, m_floatY = 100;
	float m_floatW = 350, m_floatH = 400;
	bool  m_floatDragging = false;
	float m_floatDragOffX = 0, m_floatDragOffY = 0;
	// Saved main window state (restored after floating window)
	float m_savedContentX = 0, m_savedContentY = 0;
	float m_savedContentW = 0, m_savedContentH = 0;
	float m_savedCursorY = 0;
	float m_savedClipTop = 0, m_savedClipBottom = 99999;

	// Style constants - BlueLock Premium
	static constexpr float TITLE_BAR_HEIGHT = 42;
	static constexpr float SIDEBAR_WIDTH = 145;
	static constexpr float TAB_HEIGHT = 36;
	static constexpr float WIDGET_HEIGHT = 30;
	static constexpr float WIDGET_SPACING = 5;
	static constexpr float SECTION_SPACING = 14;
	static constexpr float PADDING = 16;
	static constexpr float SECTION_ACCENT_WIDTH = 3;
	static constexpr float TOGGLE_WIDTH = 44;
	static constexpr float TOGGLE_HEIGHT = 22;
	static constexpr float SLIDER_HEIGHT = 4;
	static constexpr float SLIDER_KNOB_RADIUS = 7;
};

// Global menu instance
extern Menu g_menu;

} // namespace CustomMenu
