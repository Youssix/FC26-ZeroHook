#include "frostbite_input.h"
#include "../offsets/offsets.h"
#include "../hook/dxgi_hooks.h"
#include "../log/log.h"
#include "../log/fmt.h"

void FrostbiteInput::BlockGameInput(bool block)
{
    hook::set_block_input(block);
}

bool FrostbiteInput::Init()
{
    if (s_ready) return true;

    // All vtable pointers already resolved by offsets::Init()
    if (!offsets::InputReader || !offsets::FnIsKeyDown)
    {
        log::debug("[FBInput] InputReader vtable not resolved\r\n");
        return false;
    }

    s_reader = offsets::InputReader;

    // Cache vtable function pointers for our own spoof_call reads
    s_fnIsKeyDown        = (fn_sc_t) offsets::FnIsKeyDown;
    s_fnWasKeyPressed    = (fn_sc_t) offsets::FnWasKeyPressed;
    s_fnWasKeyReleased   = (fn_sc_t) offsets::FnWasKeyReleased;
    s_fnIsMouseDown      = (fn_btn_t)offsets::FnIsMouseDown;
    s_fnWasMousePressed  = (fn_btn_t)offsets::FnWasMousePressed;
    s_fnWasMouseReleased = (fn_btn_t)offsets::FnWasMouseReleased;
    s_fnGetMouseX        = (fn_int_t)offsets::FnGetMouseX;
    s_fnGetMouseY        = (fn_int_t)offsets::FnGetMouseY;
    s_fnGetMouseDeltaX   = (fn_int_t)offsets::FnGetMouseDeltaX;
    s_fnGetMouseDeltaY   = (fn_int_t)offsets::FnGetMouseDeltaY;
    s_fnGetMouseScroll   = (fn_int_t)offsets::FnGetMouseScroll;

    char buf[256];
    fmt::snprintf(buf, sizeof(buf), "[FBInput] reader=%p  isMouseDown=%p\r\n",
        (void*)s_reader, (void*)s_fnIsMouseDown);
    log::debug(buf);

    s_ready = true;
    log::debug("[FBInput] Init OK (EPT hooks handle input blocking)\r\n");
    return true;
}
