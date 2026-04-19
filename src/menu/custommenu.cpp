#include "custommenu.h"
#include "../input/frostbite_input.h"
#include "../log/fmt.h"
#include <intrin.h>

// Minimal CRT stubs for no-CRT build
extern "C" float sqrtf(float);

// Float-to-string for slider values (snprintf "%.1f" replacement)
static void float_to_str(char* buf, int bufSize, float val, int decimals)
{
	int pos = 0;
	if (val < 0) { if (pos < bufSize - 1) buf[pos++] = '-'; val = -val; }
	int intPart = (int)val;
	// Integer part
	char tmp[16]; int tlen = 0;
	if (intPart == 0) tmp[tlen++] = '0';
	else { while (intPart > 0) { tmp[tlen++] = '0' + (intPart % 10); intPart /= 10; } }
	for (int i = tlen - 1; i >= 0 && pos < bufSize - 1; i--) buf[pos++] = tmp[i];
	// Decimal part
	if (decimals > 0 && pos < bufSize - 1) {
		buf[pos++] = '.';
		float frac = val - (int)val;
		for (int d = 0; d < decimals && pos < bufSize - 1; d++) {
			frac *= 10.0f;
			int digit = (int)frac;
			buf[pos++] = '0' + (digit % 10);
			frac -= digit;
		}
	}
	buf[pos] = '\0';
}

// sinf/cosf with range reduction — Taylor only converges near zero
static float menu_sinf(float x) {
	const float PI = 3.14159265f;
	const float TWO_PI = 6.28318530f;
	// Reduce to [-PI, PI]
	x = x - TWO_PI * (float)(int)(x / TWO_PI);
	if (x > PI) x -= TWO_PI;
	if (x < -PI) x += TWO_PI;
	float x2 = x * x;
	float x3 = x2 * x;
	float x5 = x3 * x2;
	float x7 = x5 * x2;
	float x9 = x7 * x2;
	return x - x3 / 6.0f + x5 / 120.0f - x7 / 5040.0f + x9 / 362880.0f;
}

static float menu_cosf(float x) {
	const float PI = 3.14159265f;
	const float TWO_PI = 6.28318530f;
	x = x - TWO_PI * (float)(int)(x / TWO_PI);
	if (x > PI) x -= TWO_PI;
	if (x < -PI) x += TWO_PI;
	float x2 = x * x;
	float x4 = x2 * x2;
	float x6 = x4 * x2;
	float x8 = x6 * x2;
	return 1.0f - x2 / 2.0f + x4 / 24.0f - x6 / 720.0f + x8 / 40320.0f;
}
#define sinf menu_sinf
#define cosf menu_cosf

// strstr replacement
static const char* menu_strstr(const char* haystack, const char* needle) {
	if (!needle || !*needle) return haystack;
	for (const char* h = haystack; *h; h++) {
		const char* p1 = h;
		const char* p2 = needle;
		while (*p1 && *p2 && *p1 == *p2) { p1++; p2++; }
		if (!*p2) return h;
	}
	return nullptr;
}
#define strstr menu_strstr

namespace CustomMenu {

// Global menu instance
Menu g_menu;

void Menu::Init(D3D12Renderer* renderer) {
	m_renderer = renderer;
	m_isOpen = true; // menu visible on inject — toggle with INSERT/F5
	m_windowX = 50;
	m_windowY = 50;
	m_windowW = 920;
	m_windowH = 640;
	m_selectedTab = 0;
}

void Menu::Shutdown() {
	m_renderer = nullptr;
}

void Menu::BeginFrame(float screenW, float screenH, float mouseX, float mouseY, bool mouseDown, float scrollDelta) {
	m_screenW = screenW;
	m_screenH = screenH;
	m_input.Update(mouseX, mouseY, mouseDown, scrollDelta);

	// When a combo dropdown is open, save real click for EndFrame dropdown,
	// but block clicks on widgets behind it
	m_comboClickSaved = false;
	if (m_openComboID != 0 && m_input.mouseClicked) {
		m_comboClickSaved = true;
		m_input.mouseClicked = false;
	}

	// Reset per-frame state
	m_hotWidget = 0;
	m_tooltipText = nullptr;
	m_comboOpen = false;
}

void Menu::EndFrame() {
	// Draw combo dropdown overlay (MUST be before tooltip for correct z-order)
	// Restore the saved click that was blocked from widgets
	if (m_comboClickSaved) m_input.mouseClicked = true;

	if (m_openComboID != 0 && m_comboItems && m_comboValue && m_isOpen) {
		float h = WIDGET_HEIGHT;
		int visibleCount = m_comboItemCount;
		if (visibleCount > COMBO_MAX_VISIBLE) visibleCount = COMBO_MAX_VISIBLE;
		bool hasScroll = (m_comboItemCount > COMBO_MAX_VISIBLE);

		float dropH = h * visibleCount;
		float dropY = m_comboY;

		// Clamp dropdown to screen bounds
		if (dropY + dropH > m_screenH - 10) {
			dropY = m_comboY - h - dropH;  // flip above
			if (dropY < 0) dropY = 10;
		}

		// Handle scroll within dropdown
		if (hasScroll && m_input.IsInRect(m_comboX, dropY, m_comboW, dropH)) {
			float delta = m_input.scrollDelta;
			if (delta > 0 && m_comboScrollOffset > 0)
				m_comboScrollOffset--;
			else if (delta < 0 && m_comboScrollOffset < m_comboItemCount - COMBO_MAX_VISIBLE)
				m_comboScrollOffset++;
		}

		// Background with shadow effect
		DrawRect(m_comboX - 1, dropY - 1, m_comboW + 2, dropH + 2, {0, 0, 0, 120});
		DrawRect(m_comboX, dropY, m_comboW, dropH, Colors::Surface);
		DrawRectOutline(m_comboX, dropY, m_comboW, dropH, 1, Colors::Primary);

		// Draw visible items
		for (int vi = 0; vi < visibleCount; vi++) {
			int i = vi + m_comboScrollOffset;
			if (i < 0 || i >= m_comboItemCount) continue;

			float itemY = dropY + vi * h;
			bool itemHover = m_input.IsInRect(m_comboX, itemY, m_comboW, h);
			bool isSelected = (i == *m_comboValue);

			if (itemHover) {
				DrawRect(m_comboX, itemY, m_comboW, h, Colors::SurfaceHover);
			}
			if (isSelected) {
				DrawRect(m_comboX, itemY, m_comboW, h, {Colors::Primary.r, Colors::Primary.g, Colors::Primary.b, 40});
				DrawRect(m_comboX, itemY, SECTION_ACCENT_WIDTH, h, Colors::Primary);
			}

			const char* itemText = m_comboItems[i];
			if (itemText)
				DrawText(m_comboX + 10, itemY + (h - 16) / 2, itemText,
				         isSelected ? Colors::PrimaryGlow : Colors::Text);

			if (itemHover && m_input.mouseClicked) {
				*m_comboValue = i;
				m_comboChanged = true;
				m_openComboID = 0;
				m_input.mouseClicked = false; // consume click so widgets behind don't trigger
			}
		}

		// Scroll indicator
		if (hasScroll) {
			float scrollBarW = 4;
			float scrollBarX = m_comboX + m_comboW - scrollBarW - 2;
			float scrollRatio = (float)m_comboScrollOffset / (float)(m_comboItemCount - COMBO_MAX_VISIBLE);
			float barH = dropH * ((float)COMBO_MAX_VISIBLE / m_comboItemCount);
			if (barH < 15) barH = 15;
			float barY = dropY + scrollRatio * (dropH - barH);
			DrawRect(scrollBarX, barY, scrollBarW, barH, Colors::Primary);
		}

		// Close if clicking outside dropdown AND outside combo box
		float comboBoxY = m_comboY - h;  // the combo box is h pixels above dropdown
		if (m_input.mouseClicked &&
		    !m_input.IsInRect(m_comboX, dropY, m_comboW, dropH) &&
		    !m_input.IsInRect(m_comboX, comboBoxY, m_comboW, h)) {
			m_openComboID = 0;
			m_input.mouseClicked = false; // consume click
		}
	}

	// Draw tooltip if any
	if (m_tooltipText && m_isOpen) {
		float padding = 8;
		float textW = MeasureText(m_tooltipText, 1.0f);
		float textH = m_renderer ? m_renderer->GetFontHeight() : 16;

		float x = m_tooltipX + 15;
		float y = m_tooltipY + 15;

		// Keep on screen
		if (x + textW + padding * 2 > m_screenW) x = m_screenW - textW - padding * 2 - 5;
		if (y + textH + padding * 2 > m_screenH) y = m_screenH - textH - padding * 2 - 5;

		// Dark background with accent top border
		DrawRect(x, y, textW + padding * 2, textH + padding * 2, Colors::Surface);
		DrawRect(x, y, textW + padding * 2, 2, Colors::Primary);  // Top accent
		DrawRectOutline(x, y, textW + padding * 2, textH + padding * 2, 1, Colors::Border);
		DrawText(x + padding, y + padding + 1, m_tooltipText, Colors::Text);
	}

	// Clear active widget if mouse released
	if (m_input.mouseReleased && m_activeWidget != 0) {
		m_activeWidget = 0;
	}
}

bool Menu::WantsMouse() const {
	if (!m_isOpen) return false;
	return m_input.IsInRect(m_windowX, m_windowY, m_windowW, m_windowH);
}

// ============================================================================
// Drawing Helpers
// ============================================================================

void Menu::DrawRect(float x, float y, float w, float h, const Color& c) {
	if (m_renderer) {
		m_renderer->DrawRect(x, y, w, h, c.r, c.g, c.b, c.a * m_opacity);
	}
}

void Menu::DrawRectOutline(float x, float y, float w, float h, float thickness, const Color& c) {
	if (m_renderer) {
		m_renderer->DrawRectOutline(x, y, w, h, thickness, c.r, c.g, c.b, c.a * m_opacity);
	}
}

void Menu::DrawText(float x, float y, const char* text, const Color& c, float scale) {
	if (m_renderer) {
		m_renderer->DrawText(x, y, text, c.r, c.g, c.b, c.a * m_opacity, scale);
	}
}

float Menu::MeasureText(const char* text, float scale) {
	if (m_renderer) {
		return m_renderer->MeasureText(text, scale);
	}
	return 0;
}

void Menu::DrawCircle(float cx, float cy, float radius, const Color& c, int segments) {
	if (!m_renderer) return;

	const float PI = 3.14159265f;
	for (int i = 0; i < segments; i++) {
		float angle1 = (float)i * 2.0f * PI / (float)segments;
		float angle2 = (float)(i + 1) * 2.0f * PI / (float)segments;

		float x1 = cx + cosf(angle1) * radius;
		float y1 = cy + sinf(angle1) * radius;
		float x2 = cx + cosf(angle2) * radius;
		float y2 = cy + sinf(angle2) * radius;

		DrawTriangle(cx, cy, x1, y1, x2, y2, c);
	}
}

void Menu::DrawTriangle(float x1, float y1, float x2, float y2, float x3, float y3, const Color& c) {
	if (m_renderer) {
		m_renderer->DrawTriangle(x1, y1, x2, y2, x3, y3, c.r, c.g, c.b, c.a * m_opacity);
	}
}

// ============================================================================
// Scroll & Clipping
// ============================================================================

void Menu::SetScrollInput(float delta) {
	if (delta != 0 && m_isOpen) {
		// Block parent scroll when combo dropdown is open (scroll handled in EndFrame)
		if (m_openComboID != 0) return;

		// Only scroll when mouse is over content area
		if (m_input.mouseX > m_windowX + SIDEBAR_WIDTH &&
		    m_input.mouseX < m_windowX + m_windowW &&
		    m_input.mouseY > m_windowY + TITLE_BAR_HEIGHT &&
		    m_input.mouseY < m_windowY + m_windowH) {
			m_scrollY -= delta * 0.3f;
			if (m_scrollY < 0) m_scrollY = 0;
		}
	}
}

bool Menu::IsWidgetVisible(float y, float h) const {
	return (y + h > m_clipTop && y < m_clipBottom);
}

// ============================================================================
// Widget ID System
// ============================================================================

WidgetID Menu::GetID(const char* label) {
	WidgetID base = 0;
	for (int i = 0; i < m_idStackSize; i++) {
		base ^= m_idStack[i];
	}
	return base ^ HashString(label);
}

// ============================================================================
// Layout
// ============================================================================

void Menu::AdvanceCursor(float h) {
	m_cursorY += h + WIDGET_SPACING;
}

float Menu::GetContentWidth() const {
	if (m_rowColumns > 1) {
		return m_columnWidth - PADDING;
	}
	return m_contentW - PADDING * 2;
}

// ============================================================================
// Window - BlueLock Sidebar Layout
// ============================================================================

bool Menu::BeginWindow(const char* title, float minW, float minH) {
	if (!m_isOpen || !m_renderer) return false;

	float titleBarH = TITLE_BAR_HEIGHT;

	// Handle window dragging (title bar area)
	if (m_input.IsInRect(m_windowX, m_windowY, m_windowW, titleBarH)) {
		if (m_input.mouseClicked) {
			m_dragging = true;
			m_dragOffsetX = m_input.mouseX - m_windowX;
			m_dragOffsetY = m_input.mouseY - m_windowY;
		}
	}

	if (m_dragging) {
		if (m_input.mouseDown) {
			m_windowX = m_input.mouseX - m_dragOffsetX;
			m_windowY = m_input.mouseY - m_dragOffsetY;
			// Allow moving partially offscreen — keep at least 100px of title bar visible
			float minVisible = 100.0f;
			if (m_windowX + m_windowW < minVisible) m_windowX = minVisible - m_windowW;
			if (m_windowY < -m_windowH + TITLE_BAR_HEIGHT) m_windowY = -m_windowH + TITLE_BAR_HEIGHT;
			if (m_windowX > m_screenW - minVisible) m_windowX = m_screenW - minVisible;
			if (m_windowY > m_screenH - TITLE_BAR_HEIGHT) m_windowY = m_screenH - TITLE_BAR_HEIGHT;
		} else {
			m_dragging = false;
		}
	}

	// === Window Background ===
	DrawRect(m_windowX, m_windowY, m_windowW, m_windowH, Colors::Background);

	// === Sidebar ===
	DrawRect(m_windowX, m_windowY, SIDEBAR_WIDTH, m_windowH, Colors::Sidebar);

	// === Title bar (full width, dark) ===
	DrawRect(m_windowX, m_windowY, m_windowW, titleBarH, Colors::Sidebar);

	// Top accent line (electric blue)
	DrawRect(m_windowX, m_windowY, m_windowW, 2, Colors::Primary);

	// Title text in content area header
	DrawText(m_windowX + SIDEBAR_WIDTH + PADDING, m_windowY + titleBarH / 2 - 6, "ZeroHook Menu", Colors::TextDisabled);

	// Close button (top right)
	float closeSize = 22;
	float closeX = m_windowX + m_windowW - closeSize - 10;
	float closeY = m_windowY + (titleBarH - closeSize) / 2 + 1;
	bool closeHover = m_input.IsInRect(closeX, closeY, closeSize, closeSize);

	if (closeHover) {
		DrawRect(closeX, closeY, closeSize, closeSize, Colors::Secondary);
	}
	float xTextW = MeasureText("X", 1.0f);
	DrawText(closeX + (closeSize - xTextW) / 2, closeY + 3, "X",
	         closeHover ? Colors::Text : Colors::TextSecondary);

	if (closeHover && m_input.mouseClicked) {
		m_isOpen = false;
		return false;
	}

	// Separator below title bar
	DrawRect(m_windowX, m_windowY + titleBarH, m_windowW, 1, Colors::Border);

	// Sidebar vertical separator
	DrawRect(m_windowX + SIDEBAR_WIDTH, m_windowY + titleBarH, 1, m_windowH - titleBarH, Colors::Border);

	// Sidebar bottom branding
	float footerY = m_windowY + m_windowH - 28;
	DrawRect(m_windowX, footerY, SIDEBAR_WIDTH, 1, Colors::Border);
	float verW = MeasureText("v1.0", 0.85f);
	DrawText(m_windowX + (SIDEBAR_WIDTH - verW) / 2, footerY + 7, "v1.0", Colors::TextDisabled, 0.85f);

	// Window outer border
	DrawRectOutline(m_windowX, m_windowY, m_windowW, m_windowH, 1, Colors::Border);

	// Set content area to RIGHT of sidebar
	m_contentX = m_windowX + SIDEBAR_WIDTH + 1 + PADDING;
	m_contentY = m_windowY + titleBarH + 1 + PADDING;
	m_contentW = m_windowW - SIDEBAR_WIDTH - 1 - PADDING * 2;
	m_contentH = m_windowH - titleBarH - 1 - PADDING * 2;

	// Clip bounds for content area
	m_clipTop = m_contentY;
	m_clipBottom = m_contentY + m_contentH;

	// Apply scroll offset to cursor
	m_cursorY = m_contentY - m_scrollY;

	return true;
}

void Menu::EndWindow() {
	// Calculate total content height and clamp scroll
	float totalH = m_cursorY - (m_contentY - m_scrollY);
	float maxScroll = totalH - m_contentH;
	if (maxScroll < 0) maxScroll = 0;
	if (m_scrollY > maxScroll) m_scrollY = maxScroll;
	if (m_scrollY < 0) m_scrollY = 0;

	// Draw scrollbar if content overflows
	if (maxScroll > 0) {
		float barW = 4;
		float barX = m_windowX + m_windowW - barW - 4;
		float areaH = m_contentH;
		float barH = (m_contentH / totalH) * areaH;
		if (barH < 20) barH = 20;
		float barY = m_clipTop + (m_scrollY / maxScroll) * (areaH - barH);

		DrawRect(barX, barY, barW, barH, Colors::TextDisabled);
	}
}

// ============================================================================
// Tabs - Vertical Sidebar
// ============================================================================

void Menu::BeginTabs() {
	m_tabCount = 0;
	// Tabs start below title bar + separator in sidebar
	m_tabY = m_windowY + TITLE_BAR_HEIGHT + 1 + 8;
}

bool Menu::Tab(const char* label, int index) {
	float tabW = SIDEBAR_WIDTH;
	float tabH = TAB_HEIGHT;
	float tabX = m_windowX;
	float tabY = m_tabY + index * tabH;

	bool isSelected = (m_selectedTab == index);
	bool isHover = m_input.IsInRect(tabX, tabY, tabW, tabH);

	// Background
	if (isSelected) {
		DrawRect(tabX, tabY, tabW, tabH, Colors::SidebarActive);
		// Left accent bar
		DrawRect(tabX, tabY, SECTION_ACCENT_WIDTH, tabH, Colors::Primary);
	} else if (isHover) {
		DrawRect(tabX, tabY, tabW, tabH, Colors::SidebarHover);
	}

	// Text
	Color textColor = isSelected ? Colors::Primary : (isHover ? Colors::Text : Colors::TextSecondary);
	float textX = tabX + SECTION_ACCENT_WIDTH + 14;
	float textY = tabY + (tabH - 16) / 2;
	DrawText(textX, textY, label, textColor);

	// Handle click
	if (isHover && m_input.mouseClicked) {
		if (m_selectedTab != index) {
			m_scrollY = 0;
			m_openComboID = 0;   // close any open combo dropdown
			m_activeWidget = 0;  // release any active slider drag
		}
		m_selectedTab = index;
		return true;
	}

	m_tabCount++;
	return false;
}

void Menu::TabDisabled(const char* label, int index) {
	float tabW = SIDEBAR_WIDTH;
	float tabH = TAB_HEIGHT;
	float tabX = m_windowX;
	float tabY = m_tabY + index * tabH;

	// Very dim text - clearly disabled
	float textX = tabX + SECTION_ACCENT_WIDTH + 14;
	float textY = tabY + (tabH - 16) / 2;

	// Draw subtle strikethrough line
	DrawText(textX, textY, label, Colors::TextDisabled);
	float labelW = MeasureText(label, 1.0f);
	DrawRect(textX, textY + 8, labelW, 1, Colors::TextDisabled);

	m_tabCount++;
}

void Menu::EndTabs() {
	// Tabs are in the sidebar - do NOT advance content cursor
	// Content area cursor was already set by BeginWindow
}

// ============================================================================
// Section - Left Accent Bar
// ============================================================================

bool Menu::BeginSection(const char* title) {
	m_inSection = true;

	float headerH = 26;

	// Only draw header if visible
	if (IsWidgetVisible(m_cursorY, headerH + 6)) {
		// Left accent bar
		DrawRect(m_contentX, m_cursorY, SECTION_ACCENT_WIDTH, headerH, Colors::Primary);

		// Section title
		if (title && title[0] != '\0') {
			DrawText(m_contentX + SECTION_ACCENT_WIDTH + 10, m_cursorY + 5, title, Colors::Text);
		}

		// Subtle separator line under header
		DrawRect(m_contentX, m_cursorY + headerH + 1, m_contentW, 1, Colors::Border);
	}

	m_cursorY += headerH + 2;
	m_cursorY += 4;

	// Push indent
	m_contentX += m_sectionIndent;
	m_contentW -= m_sectionIndent * 2;

	return true;
}

void Menu::EndSection() {
	// Pop indent
	m_contentX -= m_sectionIndent;
	m_contentW += m_sectionIndent * 2;

	m_cursorY += SECTION_SPACING;
	m_inSection = false;
}

// ============================================================================
// Widgets
// ============================================================================

bool Menu::Toggle(const char* label, bool* value, const char* tooltip) {
	if (!value) return false;

	float y = m_cursorY;
	float h = WIDGET_HEIGHT;
	if (!IsWidgetVisible(y, h)) { AdvanceCursor(h); return false; }

	WidgetID id = GetID(label);
	float contentW = GetContentWidth();
	float toggleX = m_contentX + contentW - TOGGLE_WIDTH;

	bool isHover = m_input.IsInRect(m_contentX, y, contentW, h);
	if (isHover) SetHot(id);

	// Hover background (subtle)
	if (isHover) {
		DrawRect(m_contentX - 6, y - 1, contentW + 12, h + 2, Colors::SurfaceHover);
	}

	// Label - strip ## suffix for display
	const char* toggleDisplayLabel = label;
	char toggleCleanLabel[128];
	const char* toggleHashPos = strstr(label, "##");
	if (toggleHashPos) {
		int len = (int)(toggleHashPos - label);
		if (len > 127) len = 127;
		__movsb(reinterpret_cast<unsigned char*>(toggleCleanLabel), reinterpret_cast<const unsigned char*>(label), len);
		toggleCleanLabel[len] = 0;
		toggleDisplayLabel = toggleCleanLabel;
	}
	DrawText(m_contentX, y + (h - 16) / 2, toggleDisplayLabel, isHover ? Colors::Text : Colors::TextSecondary);

	// Pill-shaped toggle track
	float trackX = toggleX;
	float trackY = y + (h - TOGGLE_HEIGHT) / 2;
	float radius = TOGGLE_HEIGHT / 2.0f;
	Color trackColor = *value ? Colors::Primary : Colors::Surface;

	// Draw pill: left semicircle + center rect + right semicircle
	DrawCircle(trackX + radius, trackY + radius, radius, trackColor, 20);
	DrawRect(trackX + radius, trackY, TOGGLE_WIDTH - TOGGLE_HEIGHT, TOGGLE_HEIGHT, trackColor);
	DrawCircle(trackX + TOGGLE_WIDTH - radius, trackY + radius, radius, trackColor, 20);

	// Knob (circle)
	float knobRadius = radius - 3.0f;
	float knobCX = *value ? (trackX + TOGGLE_WIDTH - radius) : (trackX + radius);
	float knobCY = trackY + radius;
	DrawCircle(knobCX, knobCY, knobRadius, Colors::Text, 16);

	// Handle click
	bool changed = false;
	if (isHover && m_input.mouseClicked) {
		*value = !*value;
		changed = true;
	}

	// Tooltip
	if (isHover && tooltip) {
		m_tooltipText = tooltip;
		m_tooltipX = m_input.mouseX;
		m_tooltipY = m_input.mouseY;
	}

	AdvanceCursor(h);
	return changed;
}

bool Menu::SliderFloat(const char* label, float* value, float minVal, float maxVal,
                       const char* format, const char* tooltip) {
	if (!value) return false;

	float y = m_cursorY;
	float h = WIDGET_HEIGHT + 10;
	if (!IsWidgetVisible(y, h)) { AdvanceCursor(h); return false; }

	WidgetID id = GetID(label);
	float contentW = GetContentWidth();

	float sliderW = contentW - 60;
	float sliderX = m_contentX;
	float sliderY = y + 20;

	bool isHover = m_input.IsInRect(sliderX, sliderY - 5, sliderW, SLIDER_HEIGHT + 14);
	if (isHover) SetHot(id);

	// Label - strip ## suffix for display
	const char* sliderDisplayLabel = label;
	char sliderCleanLabel[128];
	const char* sliderHashPos = strstr(label, "##");
	if (sliderHashPos) {
		int len = (int)(sliderHashPos - label);
		if (len > 127) len = 127;
		__movsb(reinterpret_cast<unsigned char*>(sliderCleanLabel), reinterpret_cast<const unsigned char*>(label), len);
		sliderCleanLabel[len] = 0;
		sliderDisplayLabel = sliderCleanLabel;
	}
	DrawText(m_contentX, y, sliderDisplayLabel, Colors::TextSecondary);

	// Value text
	char valStr[32];
	float_to_str(valStr, sizeof(valStr), *value, 1);
	float valW = MeasureText(valStr, 1.0f);
	DrawText(m_contentX + contentW - valW, y, valStr, Colors::PrimaryGlow);

	// Slider track (thin, modern)
	DrawRect(sliderX, sliderY, sliderW, SLIDER_HEIGHT, Colors::Surface);

	// Filled portion
	float t = (*value - minVal) / (maxVal - minVal);
	if (t < 0) t = 0;
	if (t > 1) t = 1;
	float filledW = t * sliderW;
	DrawRect(sliderX, sliderY, filledW, SLIDER_HEIGHT, Colors::Primary);

	// Knob (circle)
	float knobCX = sliderX + filledW;
	float knobCY = sliderY + SLIDER_HEIGHT / 2.0f;
	Color knobColor = (isHover || IsActive(id)) ? Colors::PrimaryGlow : Colors::Text;
	DrawCircle(knobCX, knobCY, SLIDER_KNOB_RADIUS, knobColor, 16);

	// Handle drag
	bool changed = false;
	if (IsActive(id) || (isHover && m_input.mouseClicked)) {
		SetActive(id);
		if (m_input.mouseDown) {
			float newT = (m_input.mouseX - sliderX) / sliderW;
			if (newT < 0) newT = 0;
			if (newT > 1) newT = 1;
			float newVal = minVal + newT * (maxVal - minVal);
			// Snap to integer when the display format is integer-only ("%.0f")
			if (format && format[0] == '%' && format[1] == '.' && format[2] == '0' && format[3] == 'f') {
				newVal = (float)(int)(newVal + (newVal >= 0 ? 0.5f : -0.5f));
			}
			if (newVal != *value) {
				*value = newVal;
				changed = true;
			}
		} else {
			ClearActive();
		}
	}

	if (isHover && tooltip) {
		m_tooltipText = tooltip;
		m_tooltipX = m_input.mouseX;
		m_tooltipY = m_input.mouseY;
	}

	AdvanceCursor(h);
	return changed;
}

bool Menu::SliderInt(const char* label, int* value, int minVal, int maxVal, const char* tooltip) {
	float fval = (float)*value;
	bool changed = SliderFloat(label, &fval, (float)minVal, (float)maxVal, "%.0f", tooltip);
	*value = (int)fval;
	return changed;
}

bool Menu::Button(const char* label, float width, float height) {
	return ButtonColored(label, Colors::Primary, width, height);
}

bool Menu::ButtonColored(const char* label, const Color& color, float width, float height) {
	float y = m_cursorY;
	float h = height;
	if (!IsWidgetVisible(y, h)) { AdvanceCursor(h); return false; }

	WidgetID id = GetID(label);
	float w = (width < 0) ? GetContentWidth() : width;
	float x = m_contentX;

	bool isHover = m_input.IsInRect(x, y, w, h);
	if (isHover) SetHot(id);

	// Background with states
	Color bgColor = color;
	if (m_input.mouseDown && isHover) {
		bgColor = color.WithAlpha(0.6f);
	} else if (isHover) {
		bgColor = color.WithAlpha(0.85f);
	}
	DrawRect(x, y, w, h, bgColor);
	DrawRectOutline(x, y, w, h, 1, color.WithAlpha(0.4f));  // Subtle border

	// Text centered - strip ## suffix for display
	const char* displayLabel = label;
	char cleanLabel[128];
	const char* hashPos = strstr(label, "##");
	if (hashPos) {
		int len = (int)(hashPos - label);
		if (len > 127) len = 127;
		__movsb(reinterpret_cast<unsigned char*>(cleanLabel), reinterpret_cast<const unsigned char*>(label), len);
		cleanLabel[len] = '\0';
		displayLabel = cleanLabel;
	}

	float textW = MeasureText(displayLabel, 1.0f);
	float textH = m_renderer ? m_renderer->GetFontHeight() : 16;
	DrawText(x + (w - textW) / 2, y + (h - textH) / 2, displayLabel, Colors::Text);

	AdvanceCursor(h);

	return isHover && m_input.mouseClicked;
}

bool Menu::Combo(const char* label, int* currentIndex, const char** items, int itemCount) {
	if (!currentIndex || !items || itemCount <= 0) return false;

	float y = m_cursorY;
	float h = WIDGET_HEIGHT;
	if (!IsWidgetVisible(y, h)) { AdvanceCursor(h); return false; }

	WidgetID id = GetID(label);
	float contentW = GetContentWidth();

	float comboW = 210;
	float comboX = m_contentX + contentW - comboW;
	float comboY = y;

	bool isHover = m_input.IsInRect(comboX, comboY, comboW, h);
	if (isHover) SetHot(id);

	// Label text
	DrawText(m_contentX, y + (h - 16) / 2, label, Colors::TextSecondary);

	// Combo box background
	bool isOpen = (m_openComboID == id);
	Color bgColor = (isHover || isOpen) ? Colors::SurfaceHover : Colors::Surface;
	DrawRect(comboX, comboY, comboW, h, bgColor);
	DrawRectOutline(comboX, comboY, comboW, h, 1, (isHover || isOpen) ? Colors::Primary : Colors::Border);

	// Current selection text
	const char* currentText = (*currentIndex >= 0 && *currentIndex < itemCount)
	                          ? items[*currentIndex] : "Select...";
	if (!currentText) currentText = "???";
	DrawText(comboX + 10, comboY + (h - 16) / 2, currentText, Colors::Text);

	// Dropdown arrow
	float arrowX = comboX + comboW - 20;
	float arrowY = comboY + h / 2;
	Color arrowCol = (isHover || isOpen) ? Colors::Primary : Colors::TextSecondary;
	if (isOpen)
		DrawTriangle(arrowX, arrowY + 3, arrowX + 10, arrowY + 3, arrowX + 5, arrowY - 3, arrowCol);
	else
		DrawTriangle(arrowX, arrowY - 3, arrowX + 10, arrowY - 3, arrowX + 5, arrowY + 3, arrowCol);

	// Handle click to toggle open/close
	if (isHover && m_input.mouseClicked) {
		if (m_openComboID == id) {
			m_openComboID = 0;
		} else {
			m_openComboID = id;
			m_comboX = comboX;
			m_comboY = comboY + h;
			m_comboW = comboW;
			m_comboItems = items;
			m_comboItemCount = itemCount;
			m_comboValue = currentIndex;
			m_comboScrollOffset = 0;
			m_comboChanged = false;
			// Auto-scroll to show selected item
			if (*currentIndex >= COMBO_MAX_VISIBLE)
				m_comboScrollOffset = *currentIndex - COMBO_MAX_VISIBLE / 2;
			if (m_comboScrollOffset < 0) m_comboScrollOffset = 0;
			if (m_comboScrollOffset > itemCount - COMBO_MAX_VISIBLE)
				m_comboScrollOffset = itemCount - COMBO_MAX_VISIBLE;
			if (m_comboScrollOffset < 0) m_comboScrollOffset = 0;
		}
	}

	// Check if combo changed this frame (set by EndFrame dropdown click)
	bool changed = false;
	if (m_comboChanged && m_comboValue == currentIndex) {
		changed = true;
		m_comboChanged = false;
	}

	AdvanceCursor(h);
	return changed;
}

void Menu::Label(const char* text, const Color& color) {
	float y = m_cursorY;
	if (IsWidgetVisible(y, 16)) {
		DrawText(m_contentX, y, text, color);
	}
	AdvanceCursor(16);
}

void Menu::LabelValue(const char* label, const char* value) {
	float y = m_cursorY;
	float h = 20;

	if (IsWidgetVisible(y, h)) {
		DrawText(m_contentX, y, label, Colors::TextSecondary);
		float labelW = MeasureText(label, 1.0f);
		DrawText(m_contentX + labelW + 10, y, value, Colors::PrimaryGlow);
	}

	AdvanceCursor(h);
}

void Menu::Spacing(float pixels) {
	m_cursorY += pixels;
}

void Menu::Separator() {
	m_cursorY += 4;
	if (IsWidgetVisible(m_cursorY, 1)) {
		DrawRect(m_contentX, m_cursorY, m_contentW, 1, Colors::Border);
	}
	m_cursorY += 5;
}

bool Menu::InputText(const char* label, char* buffer, int bufferSize) {
	float y = m_cursorY;
	float h = WIDGET_HEIGHT;
	if (!IsWidgetVisible(y, h)) { AdvanceCursor(h); return false; }

	WidgetID id = GetID(label);
	float contentW = GetContentWidth();

	float inputW = 210;
	float inputX = m_contentX + contentW - inputW;

	bool isHover = m_input.IsInRect(inputX, y, inputW, h);
	if (isHover) SetHot(id);

	bool focused = IsActive(id);

	// Click to focus / click outside to unfocus
	if (isHover && m_input.mouseClicked)
		SetActive(id);
	else if (!isHover && m_input.mouseClicked && focused)
		ClearActive();

	// Keyboard input when focused
	bool changed = false;
	if (focused)
	{
		int len = 0;
		while (len < bufferSize - 1 && buffer[len]) len++;

		// Backspace
		if (FrostbiteInput::WasVKeyPressed(VK_BACK) && len > 0)
		{
			buffer[--len] = '\0';
			changed = true;
		}

		// Escape / Enter → unfocus
		if (FrostbiteInput::WasVKeyPressed(VK_ESCAPE) ||
			FrostbiteInput::WasVKeyPressed(VK_RETURN))
		{
			ClearActive();
		}

		bool shift = FrostbiteInput::IsVKeyDown(VK_SHIFT);

		// A-Z
		for (int vk = 'A'; vk <= 'Z' && len < bufferSize - 1; vk++)
		{
			if (FrostbiteInput::WasVKeyPressed(vk))
			{
				buffer[len++] = shift ? (char)vk : (char)(vk + 32);
				buffer[len] = '\0';
				changed = true;
			}
		}

		// 0-9
		for (int vk = '0'; vk <= '9' && len < bufferSize - 1; vk++)
		{
			if (FrostbiteInput::WasVKeyPressed(vk))
			{
				buffer[len++] = (char)vk;
				buffer[len] = '\0';
				changed = true;
			}
		}

		// Space, minus/underscore, period
		if (len < bufferSize - 1 && FrostbiteInput::WasVKeyPressed(VK_SPACE))
		{
			buffer[len++] = ' ';
			buffer[len] = '\0';
			changed = true;
		}
		if (len < bufferSize - 1 && FrostbiteInput::WasVKeyPressed(VK_OEM_MINUS))
		{
			buffer[len++] = shift ? '_' : '-';
			buffer[len] = '\0';
			changed = true;
		}
		if (len < bufferSize - 1 && FrostbiteInput::WasVKeyPressed(VK_OEM_PERIOD))
		{
			buffer[len++] = '.';
			buffer[len] = '\0';
			changed = true;
		}
	}

	// Label
	DrawText(m_contentX, y + (h - 16) / 2, label, Colors::TextSecondary);

	// Input box — highlight when focused
	Color bgColor = focused ? Color{0.08f, 0.12f, 0.20f, 1.0f}
	               : isHover ? Colors::SurfaceHover : Colors::Surface;
	Color borderColor = focused ? Colors::PrimaryGlow
	                  : isHover ? Colors::Primary : Colors::Border;
	DrawRect(inputX, y, inputW, h, bgColor);
	DrawRectOutline(inputX, y, inputW, h, 1, borderColor);

	// Text + blinking cursor when focused
	DrawText(inputX + 10, y + (h - 16) / 2, buffer, Colors::Text);
	if (focused)
	{
		float textW = MeasureText(buffer);
		float cursorX = inputX + 10 + textW + 2;
		DrawRect(cursorX, y + 6, 1, h - 12, Colors::Text);
	}

	AdvanceCursor(h);
	return changed;
}

void Menu::StatusIndicator(const char* label, bool active, const char* tooltip) {
	float y = m_cursorY;
	float h = 22;
	if (!IsWidgetVisible(y, h)) { AdvanceCursor(h); return; }

	// Circle status dot
	float dotRadius = 5;
	Color dotColor = active ? Colors::Success : Colors::Secondary;
	float dotCX = m_contentX + dotRadius;
	float dotCY = y + h / 2;
	DrawCircle(dotCX, dotCY, dotRadius, dotColor, 12);

	// Subtle glow ring when active
	if (active) {
		DrawCircle(dotCX, dotCY, dotRadius + 2, dotColor.WithAlpha(0.2f), 12);
	}

	// Label
	DrawText(m_contentX + dotRadius * 2 + 10, y + 3, label,
	         active ? Colors::Text : Colors::TextSecondary);

	// Tooltip
	bool isHover = m_input.IsInRect(m_contentX, y, GetContentWidth(), h);
	if (isHover && tooltip) {
		m_tooltipText = tooltip;
		m_tooltipX = m_input.mouseX;
		m_tooltipY = m_input.mouseY;
	}

	AdvanceCursor(h);
}

// ============================================================================
// Row Layout
// ============================================================================

void Menu::BeginRow(int columns) {
	m_rowColumns = columns;
	m_currentColumn = 0;
	m_rowStartY = m_cursorY;
	m_rowMaxH = 0;
	m_columnWidth = m_contentW / columns;
}

void Menu::NextColumn() {
	m_currentColumn++;
	if (m_currentColumn < m_rowColumns) {
		float usedH = m_cursorY - m_rowStartY;
		if (usedH > m_rowMaxH) m_rowMaxH = usedH;

		m_cursorY = m_rowStartY;
		m_contentX += m_columnWidth;
	}
}

void Menu::EndRow() {
	m_contentX -= m_columnWidth * m_currentColumn;

	float usedH = m_cursorY - m_rowStartY;
	if (usedH > m_rowMaxH) m_rowMaxH = usedH;

	m_cursorY = m_rowStartY + m_rowMaxH;
	m_rowColumns = 1;
	m_currentColumn = 0;
	m_columnWidth = 0;
}

void Menu::SetTooltip(const char* text) {
	m_tooltipText = text;
	m_tooltipX = m_input.mouseX;
	m_tooltipY = m_input.mouseY;
}

// ============================================================================
// Floating Window - BlueLock Style
// ============================================================================

bool Menu::BeginFloatingWindow(const char* title, float defaultX, float defaultY, float defaultW, float defaultH, bool* open) {
	if (!m_renderer) return false;
	if (open && !*open) return false;

	static bool firstUse = true;
	if (firstUse) {
		m_floatX = defaultX;
		m_floatY = defaultY;
		m_floatW = defaultW;
		m_floatH = defaultH;
		firstUse = false;
	}

	// Save main window content state
	m_savedContentX = m_contentX;
	m_savedContentY = m_contentY;
	m_savedContentW = m_contentW;
	m_savedContentH = m_contentH;
	m_savedCursorY = m_cursorY;
	m_savedClipTop = m_clipTop;
	m_savedClipBottom = m_clipBottom;

	// Handle dragging
	float titleBarH = TITLE_BAR_HEIGHT;
	if (m_input.IsInRect(m_floatX, m_floatY, m_floatW, titleBarH)) {
		if (m_input.mouseClicked) {
			m_floatDragging = true;
			m_floatDragOffX = m_input.mouseX - m_floatX;
			m_floatDragOffY = m_input.mouseY - m_floatY;
		}
	}

	if (m_floatDragging) {
		if (m_input.mouseDown) {
			m_floatX = m_input.mouseX - m_floatDragOffX;
			m_floatY = m_input.mouseY - m_floatDragOffY;
			if (m_floatX < 0) m_floatX = 0;
			if (m_floatY < 0) m_floatY = 0;
			if (m_floatX + m_floatW > m_screenW) m_floatX = m_screenW - m_floatW;
			if (m_floatY + m_floatH > m_screenH) m_floatY = m_screenH - m_floatH;
		} else {
			m_floatDragging = false;
		}
	}

	// Window background
	DrawRect(m_floatX, m_floatY, m_floatW, m_floatH, Colors::Background);

	// Top accent line
	DrawRect(m_floatX, m_floatY, m_floatW, 2, Colors::Primary);

	// Title bar (dark)
	DrawRect(m_floatX, m_floatY + 2, m_floatW, titleBarH - 2, Colors::Sidebar);
	DrawText(m_floatX + PADDING, m_floatY + (titleBarH - 16) / 2 + 1, title, Colors::Primary, 1.0f);

	// Close button
	if (open) {
		float closeSize = 22;
		float closeX = m_floatX + m_floatW - closeSize - 8;
		float closeY = m_floatY + (titleBarH - closeSize) / 2 + 1;
		bool closeHover = m_input.IsInRect(closeX, closeY, closeSize, closeSize);

		if (closeHover) {
			DrawRect(closeX, closeY, closeSize, closeSize, Colors::Secondary);
		}
		float xTextW = MeasureText("X", 1.0f);
		DrawText(closeX + (closeSize - xTextW) / 2, closeY + 3, "X",
		         closeHover ? Colors::Text : Colors::TextSecondary);

		if (closeHover && m_input.mouseClicked) {
			*open = false;
			m_contentX = m_savedContentX;
			m_contentY = m_savedContentY;
			m_contentW = m_savedContentW;
			m_contentH = m_savedContentH;
			m_cursorY = m_savedCursorY;
			return false;
		}
	}

	// Separator below title
	DrawRect(m_floatX, m_floatY + titleBarH, m_floatW, 1, Colors::Border);

	// Window border
	DrawRectOutline(m_floatX, m_floatY, m_floatW, m_floatH, 1, Colors::Border);

	// Set content area (no scroll clipping for floating windows)
	m_contentX = m_floatX + PADDING;
	m_contentY = m_floatY + titleBarH + 1 + PADDING;
	m_contentW = m_floatW - PADDING * 2;
	m_contentH = m_floatH - titleBarH - 1 - PADDING * 2;
	m_cursorY = m_contentY;
	m_clipTop = m_contentY;
	m_clipBottom = m_contentY + m_contentH;

	return true;
}

void Menu::EndFloatingWindow() {
	m_contentX = m_savedContentX;
	m_contentY = m_savedContentY;
	m_contentW = m_savedContentW;
	m_contentH = m_savedContentH;
	m_cursorY = m_savedCursorY;
	m_clipTop = m_savedClipTop;
	m_clipBottom = m_savedClipBottom;
}

} // namespace CustomMenu
