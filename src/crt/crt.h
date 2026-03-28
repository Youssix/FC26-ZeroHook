#pragma once

// Minimal CRT replacements — compiler emits calls to these for struct init, copies, etc.
// Must be extern "C" with exact signatures so the linker resolves them.

extern "C" void* memcpy(void* dst, const void* src, unsigned long long size);
extern "C" void* memset(void* dst, int val, unsigned long long size);
extern "C" void* memmove(void* dst, const void* src, unsigned long long size);
extern "C" float sqrtf(float x);
extern "C" int _fltused;
