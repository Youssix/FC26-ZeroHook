#pragma once

class IRenderer {
public:

	virtual void  Shutdown() = 0;
	virtual bool  IsInitialized() const = 0;

	virtual void  DrawRect(float x, float y, float w, float h,
	                       float r, float g, float b, float a) = 0;
	virtual void  DrawRectOutline(float x, float y, float w, float h,
	                              float thickness, float r, float g, float b, float a) = 0;
	virtual void  DrawTriangle(float x1, float y1, float x2, float y2, float x3, float y3,
	                           float r, float g, float b, float a) = 0;
	virtual void  DrawLine(float x1, float y1, float x2, float y2,
	                       float thickness, float r, float g, float b, float a) = 0;
	virtual void  DrawText(float x, float y, const char* text,
	                       float r, float g, float b, float a, float scale = 1.0f) = 0;
	virtual float MeasureText(const char* text, float scale = 1.0f) = 0;
	virtual float GetFontHeight() const = 0;
};
