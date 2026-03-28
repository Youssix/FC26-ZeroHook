#include <Windows.h>
#include <intrin.h>

// Disable intrinsic expansion so we can define our own
#pragma optimize("", off)

extern "C" void* memcpy(void* dst, const void* src, unsigned long long size)
{
    __movsb(static_cast<unsigned char*>(dst), static_cast<const unsigned char*>(src), size);
    return dst;
}

extern "C" void* memset(void* dst, int val, unsigned long long size)
{
    __stosb(static_cast<unsigned char*>(dst), static_cast<unsigned char>(val), size);
    return dst;
}

extern "C" void* memmove(void* dst, const void* src, unsigned long long size)
{
    unsigned char* d = static_cast<unsigned char*>(dst);
    const unsigned char* s = static_cast<const unsigned char*>(src);
    if (d < s || d >= s + size)
    {
        __movsb(d, s, size);
    }
    else
    {
        // Overlapping, copy backward
        d += size;
        s += size;
        while (size--) *--d = *--s;
    }
    return dst;
}

// sqrtf — Newton-Raphson with SSE seed
extern "C" float sqrtf(float x)
{
    if (x <= 0.0f) return 0.0f;
    __m128 val = _mm_set_ss(x);
    val = _mm_sqrt_ss(val);
    return _mm_cvtss_f32(val);
}

// _fltused — linker expects this when floats are used without CRT
extern "C" int _fltused = 1;

// _purecall — called when a pure virtual function is invoked (shouldn't happen)
extern "C" int _purecall() { return 0; }

// operator new/delete — minimal implementations using HeapAlloc/HeapFree
void* operator new(unsigned long long size)
{
    return HeapAlloc(GetProcessHeap(), 0, size);
}

void* operator new[](unsigned long long size)
{
    return HeapAlloc(GetProcessHeap(), 0, size);
}

void operator delete(void* ptr) noexcept
{
    if (ptr) HeapFree(GetProcessHeap(), 0, ptr);
}

void operator delete[](void* ptr) noexcept
{
    if (ptr) HeapFree(GetProcessHeap(), 0, ptr);
}

void operator delete(void* ptr, unsigned long long) noexcept
{
    if (ptr) HeapFree(GetProcessHeap(), 0, ptr);
}

void operator delete[](void* ptr, unsigned long long) noexcept
{
    if (ptr) HeapFree(GetProcessHeap(), 0, ptr);
}

#pragma optimize("", on)
