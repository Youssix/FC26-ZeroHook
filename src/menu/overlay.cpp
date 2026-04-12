#include "overlay.h"
#include "menu.h"
#include "custommenu.h"
#include "toast.h"
#include "../offsets/offsets.h"
#include "../input/frostbite_input.h"
#include "../features/rage.h"
#include "../hook/network_hooks.h"
#include "../features/sliders.h"
#include "../features/competitive.h"
#include "../features/dda.h"
#include "../features/server.h"
#include "../features/division.h"
#include "../features/champions.h"
#include "../features/opponent_info.h"
#include "../features/ai_difficulty.h"
#include "../log/fmt.h"
#include "../log/log.h"
#include "../renderer/renderer.h"
#include "../spoof/spoof_call.hpp"

namespace
{
    bool           g_initialized = false;
    bool           g_rageReady   = false;
    D3D12Renderer* g_rendererPtr = nullptr;
    LARGE_INTEGER  g_lastTime    = {};

    // General tab toggles
    bool g_bypassAFK     = false;
    bool g_noLoss        = false;

    // ── Combo label arrays ──
    // IMPORTANT: manually mapped DLL doesn't relocate .data pointers.
    // Arrays of const char* in data sections contain UNRELOCATED addresses.
    // Must populate at RUNTIME via code (RIP-relative lea) instead.
    const char* g_divLabels[13];
    const char* g_reasons[14];
    const char* g_playstyles[3];
    const char* g_playstyles2[3];
    const char* g_testItems[3];
    const char* g_difficulties[7];

    void InitComboLabels()
    {
        // Division
        g_divLabels[0]="None"; g_divLabels[1]="DIV 10"; g_divLabels[2]="DIV 9";
        g_divLabels[3]="DIV 8"; g_divLabels[4]="DIV 7"; g_divLabels[5]="DIV 6";
        g_divLabels[6]="DIV 5"; g_divLabels[7]="DIV 4"; g_divLabels[8]="DIV 3";
        g_divLabels[9]="DIV 2"; g_divLabels[10]="DIV 1";
        g_divLabels[11]="ELITE 500"; g_divLabels[12]="ELITE 3000";
        // Disconnect reasons
        g_reasons[0]="Opponent Quit"; g_reasons[1]="End Match Early";
        g_reasons[2]="Squad Mismatch"; g_reasons[3]="Both Get Loss";
        g_reasons[4]="Forfeit"; g_reasons[5]="Local Idle H2H";
        g_reasons[6]="Own Goals"; g_reasons[7]="Own Goals H2H";
        g_reasons[8]="Constrained"; g_reasons[9]="Squad Error";
        g_reasons[10]="ID 19"; g_reasons[11]="ID 20";
        g_reasons[12]="ID 21"; g_reasons[13]="ID 22";
        // Playstyles
        g_playstyles[0]="None"; g_playstyles[1]="Plus"; g_playstyles[2]="Silver";
        g_playstyles2[0]="None"; g_playstyles2[1]="Plus"; g_playstyles2[2]="Silver";
        // Test
        g_testItems[0]="Option A"; g_testItems[1]="Option B"; g_testItems[2]="Option C";
        // Squad Battles difficulties
        g_difficulties[0]="Beginner"; g_difficulties[1]="Amateur"; g_difficulties[2]="Semi-Pro";
        g_difficulties[3]="Professional"; g_difficulties[4]="World Class"; g_difficulties[5]="Legendary"; g_difficulties[6]="Ultimate";
    }

    // Kick reason (shared between menu button and hotkey — available in all builds)
    int  g_dcReason = 0;

#ifndef STANDARD_BUILD
    // Rage hotkeys (default binds)
    int  hk_crash    = VK_F1;
    int  hk_freeze1  = VK_F2;
    int  hk_freeze2  = VK_F3;
    int  hk_slider   = VK_F4;
    int  hk_kick     = VK_F6;

    // Binding state
    bool hk_bind_crash   = false;
    bool hk_bind_freeze1 = false;
    bool hk_bind_freeze2 = false;
    bool hk_bind_slider  = false;
    bool hk_bind_kick    = false;

    // Hotkey action wrappers
    void hk_do_crash()   { rage::crash_opps(); }
    void hk_do_freeze1() { rage::pause_op_game(); }
    void hk_do_freeze2() { rage::pause_op_game_new(); }
    void hk_do_slider()  { rage::slider_bomb(); }
    void hk_do_kick()    { rage::kick_opponent(g_dcReason); }

    void RegisterRageHotkeys()
    {
        menu::RegisterHotkey(hk_crash,   hk_do_crash);
        menu::RegisterHotkey(hk_freeze1, hk_do_freeze1);
        menu::RegisterHotkey(hk_freeze2, hk_do_freeze2);
        menu::RegisterHotkey(hk_slider,  hk_do_slider);
        menu::RegisterHotkey(hk_kick,    hk_do_kick);
    }

    void RebindRageHotkey(int& hkVar, int newKey, void(*action)())
    {
        menu::UnregisterHotkey(hkVar);
        hkVar = newKey;
        menu::RegisterHotkey(newKey, action);
    }
#endif

#ifndef STANDARD_BUILD
    // ── Slider hotkeys (premium only) ──
    int  hk_applySliders = VK_F4;
    int  hk_swapSettings = VK_F7;
    bool hk_bind_applySliders = false;
    bool hk_bind_swapSettings = false;

    void hk_do_applySliders() { sliders::ApplySliders(); }
    void hk_do_swapSettings() { sliders::SwapSettings(); }

    void RegisterSliderHotkeys()
    {
        menu::RegisterHotkey(hk_applySliders, hk_do_applySliders);
        menu::RegisterHotkey(hk_swapSettings, hk_do_swapSettings);
    }

    void RebindSliderHotkey(int& hkVar, int newKey, void(*action)())
    {
        menu::UnregisterHotkey(hkVar);
        hkVar = newKey;
        menu::RegisterHotkey(newKey, action);
    }
#endif

    LARGE_INTEGER  g_freq        = {};

    // AI tab toggles
    bool g_aiVsOpps      = false;
    bool g_disableAi     = false;

    // Misc tab: Foul Control toggles (need per-frame access)
    bool g_noFouls       = false;
    bool g_noOffside     = false;
    bool g_noHandball    = false;
    bool g_noBooking     = false;
}

void overlay::Init(D3D12Renderer* renderer)
{
    log::debug("[OVL-INIT] overlay::Init entered\r\n");
    g_rendererPtr = renderer;

    log::debug("[OVL-INIT] InitComboLabels...\r\n");
    __try { InitComboLabels(); }
    __except (1) { log::debug("[OVL-INIT] EXCEPTION in InitComboLabels\r\n"); return; }

    log::debug("[OVL-INIT] CustomMenu::Init...\r\n");
    __try { CustomMenu::g_menu.Init(renderer); }
    __except (1) { log::debug("[OVL-INIT] EXCEPTION in CustomMenu::Init\r\n"); return; }

    CustomMenu::g_menu.SetOpen(true);

    // Only do one-time game init on first call — resizes only need renderer re-init
    static bool s_gameInitDone = false;
    if (!s_gameInitDone)
    {
        log::debug("[OVL-INIT] FrostbiteInput::Init...\r\n");
        __try { FrostbiteInput::Init(); }
        __except (1) { log::debug("[OVL-INIT] EXCEPTION in FrostbiteInput::Init\r\n"); }

        // Scan rage + slider offsets (pattern scan needs game module)
        if (offsets::GameBase && offsets::GameSize)
        {
            log::debug("[OVL-INIT] rage::InitOffsets...\r\n");
            __try { g_rageReady = rage::InitOffsets(offsets::GameBase, offsets::GameSize); }
            __except (1) { log::debug("[OVL-INIT] EXCEPTION in rage::InitOffsets\r\n"); g_rageReady = false; }
            log::debug(g_rageReady ? "[OVL-INIT] rage::InitOffsets OK\r\n" : "[OVL-INIT] rage::InitOffsets FAILED\r\n");

#ifndef STANDARD_BUILD
            log::debug("[OVL-INIT] sliders::InitOffsets...\r\n");
            __try { sliders::InitOffsets(offsets::GameBase, offsets::GameSize); }
            __except (1) { log::debug("[OVL-INIT] EXCEPTION in sliders::InitOffsets\r\n"); }
#endif

            log::debug("[OVL-INIT] server::Init...\r\n");
            __try { server::Init(offsets::GameBase, offsets::GameSize); }
            __except (1) { log::debug("[OVL-INIT] EXCEPTION in server::Init\r\n"); }

            log::debug("[OVL-INIT] champions::Init...\r\n");
            __try { champions::Init(offsets::GameBase, offsets::GameSize); }
            __except (1) { log::debug("[OVL-INIT] EXCEPTION in champions::Init\r\n"); }

            log::debug("[OVL-INIT] division::Init...\r\n");
            __try { division::Init(offsets::GameBase, offsets::GameSize); }
            __except (1) { log::debug("[OVL-INIT] EXCEPTION in division::Init\r\n"); }

            log::debug("[OVL-INIT] opp_info::Init...\r\n");
            __try { opp_info::Init(offsets::GameBase, offsets::GameSize); }
            __except (1) { log::debug("[OVL-INIT] EXCEPTION in opp_info::Init\r\n"); }
        } else {
            log::debug("[OVL-INIT] SKIP feature inits — GameBase/GameSize are NULL\r\n");
        }

        QueryPerformanceFrequency(&g_freq);
        QueryPerformanceCounter(&g_lastTime);

#ifndef STANDARD_BUILD
        log::debug("[OVL-INIT] RegisterSliderHotkeys...\r\n");
        __try { RegisterSliderHotkeys(); }
        __except (1) { log::debug("[OVL-INIT] EXCEPTION in RegisterSliderHotkeys\r\n"); }

        if (g_rageReady) {
            log::debug("[OVL-INIT] RegisterRageHotkeys...\r\n");
            __try { RegisterRageHotkeys(); }
            __except (1) { log::debug("[OVL-INIT] EXCEPTION in RegisterRageHotkeys\r\n"); }
        }
#endif

        s_gameInitDone = true;
        log::debug("[OVL-INIT] === game init complete ===\r\n");
    }

    g_initialized = true;
    log::debug("[OVL-INIT] overlay::Init complete\r\n");
}

bool overlay::IsInitialized()
{
    return g_initialized;
}

void overlay::Frame(float screenW, float screenH)
{
    static bool s_first = true;

    if (s_first) log::debug("[OVL] BlockInput(false)\r\n");
    FrostbiteInput::BlockGameInput(false);

    if (s_first) log::debug("[OVL] CheckHotkeys\r\n");
    menu::CheckHotkeys();

    // Menu toggle — manual edge detect (FC26 pattern)
    {
        static bool prevInsert = false, prevF5 = false;
        bool curInsert = FrostbiteInput::IsVKeyDown(VK_INSERT);
        bool curF5     = FrostbiteInput::IsVKeyDown(VK_F5);
        if ((curInsert && !prevInsert) || (curF5 && !prevF5))
            CustomMenu::g_menu.Toggle();
        prevInsert = curInsert;
        prevF5     = curF5;
    }

    if (s_first) log::debug("[OVL] GetMouse\r\n");
    float mouseX   = (float)FrostbiteInput::GetMouseX();
    float mouseY   = (float)FrostbiteInput::GetMouseY();
    bool  mouseDown = FrostbiteInput::IsMouseButtonDown(0);
    float scroll   = (float)FrostbiteInput::GetMouseScroll();

    if (s_first) log::debug("[OVL] ReBlock\r\n");
    FrostbiteInput::BlockGameInput(
        CustomMenu::g_menu.IsOpen() && CustomMenu::g_menu.WantsMouse());

    if (s_first) log::debug("[OVL] BeginFrame\r\n");
    CustomMenu::g_menu.SetScrollInput(scroll);
    CustomMenu::g_menu.BeginFrame(screenW, screenH, mouseX, mouseY, mouseDown, scroll);

    if (s_first) log::debug("[OVL] BeginWindow\r\n");
    if (CustomMenu::g_menu.BeginWindow("ZeroHook"))
    {
        // ── Sidebar tabs ──
        CustomMenu::g_menu.BeginTabs();
        CustomMenu::g_menu.Tab("General",       0);
        CustomMenu::g_menu.Tab("FUT",           1);
#ifndef STANDARD_BUILD
        CustomMenu::g_menu.Tab("Sliders",       2);
        CustomMenu::g_menu.Tab("Rage",          3);
#else
        CustomMenu::g_menu.TabDisabled("Sliders", 2);
        CustomMenu::g_menu.TabDisabled("Rage",    3);
#endif
        CustomMenu::g_menu.Tab("AI",            4);
        CustomMenu::g_menu.Tab("Squad Battles",  5);
        CustomMenu::g_menu.Tab("Pro Club",       6);
        CustomMenu::g_menu.Tab("Misc",           7);
        CustomMenu::g_menu.Tab("Server",         8);
        CustomMenu::g_menu.Tab("Settings",       9);
        CustomMenu::g_menu.EndTabs();

        int tab = CustomMenu::g_menu.GetSelectedTab();

        // ===================== TAB 0: General =====================
        if (tab == 0)
        {
            // ── Competitive Settings Unlock (WIP — disabled for now) ──
            // if (CustomMenu::g_menu.BeginSection("Competitive Unlock"))
            // {
            //     CustomMenu::g_menu.StatusIndicator("System", competitive::IsReady());
            //     if (competitive::IsReady())
            //     {
            //         CustomMenu::g_menu.StatusIndicator("Unlock Active", competitive::IsEnabled());
            //         bool prev = competitive::unlockEnabled;
            //         CustomMenu::g_menu.Toggle("Unlock Competitive Settings", &competitive::unlockEnabled);
            //         if (competitive::unlockEnabled != prev)
            //             competitive::SetEnabled(competitive::unlockEnabled);
            //         CustomMenu::g_menu.Label("Auto Shots, Headers, Flair Pass, Jockey...", CustomMenu::Colors::TextSecondary);
            //     }
            //     else
            //     {
            //         CustomMenu::g_menu.Label("Not initialized", CustomMenu::Colors::Warning);
            //         if (CustomMenu::g_menu.Button("Retry Init", 120, 24))
            //             competitive::Init(offsets::GameBase, offsets::GameSize);
            //     }
            //     CustomMenu::g_menu.EndSection();
            // }

            // ── DDA Bypass (WIP — disabled for now) ──
            // if (CustomMenu::g_menu.BeginSection("DDA / Momentum Bypass"))
            // {
            //     CustomMenu::g_menu.StatusIndicator("System", dda::IsReady());
            //     if (dda::IsReady())
            //     {
            //         CustomMenu::g_menu.StatusIndicator("DDA Blocked", dda::IsEnabled());
            //         bool prev = dda::bypassEnabled;
            //         CustomMenu::g_menu.Toggle("Disable Adaptive Difficulty", &dda::bypassEnabled);
            //         if (dda::bypassEnabled != prev)
            //             dda::SetEnabled(dda::bypassEnabled);
            //         CustomMenu::g_menu.Label("Removes speed nerfs, accuracy reduction", CustomMenu::Colors::TextSecondary);
            //     }
            //     else
            //     {
            //         CustomMenu::g_menu.Label("Not initialized", CustomMenu::Colors::Warning);
            //         if (CustomMenu::g_menu.Button("Retry Init##dda", 120, 24))
            //             dda::Init(offsets::GameBase, offsets::GameSize);
            //     }
            //     CustomMenu::g_menu.EndSection();
            // }

            // ── Opponent Intel ──
            if (CustomMenu::g_menu.BeginSection("Opponent Intel"))
            {
                if (!opp_info::IsReady())
                    CustomMenu::g_menu.Label("Patterns not found", CustomMenu::Colors::Warning);
                else if (!opp_info::IsHooked())
                {
                    if (CustomMenu::g_menu.ButtonColored("Install Hook##opp", CustomMenu::Colors::Primary, -1, 28))
                        opp_info::InstallHook();
                }
                else
                {
                    CustomMenu::g_menu.StatusIndicator("Hook", true);
                    CustomMenu::g_menu.Toggle("Show Opponent Window", &opp_info::g_showWindow);
                    CustomMenu::g_menu.Toggle("Extended Stats", &opp_info::g_enableStats,
                        "DR, Chemistry, Creation Date (disable if game crashes on match search)");
                }
                CustomMenu::g_menu.EndSection();
            }

            // ── Match Utilities ──
            if (CustomMenu::g_menu.BeginSection("Match Utilities"))
            {
                CustomMenu::g_menu.Toggle("Bypass Alt Tab", (bool*)&hook::g_bypass_alt_tab);
                if (hook::g_bypass_alt_tab) {
                    static bool s_altTabHooked = false;
                    if (!s_altTabHooked) {
                        hook::install_alttab_hook();
                        s_altTabHooked = true;
                    }
                }
                CustomMenu::g_menu.Toggle("Bypass AFK Detection", &g_bypassAFK);
                CustomMenu::g_menu.Toggle("No Loss on Leave", &g_noLoss);
                if (g_noLoss)
                    CustomMenu::g_menu.Label("Enable before leaving match", CustomMenu::Colors::Warning);
                CustomMenu::g_menu.EndSection();
            }

            // ── Kick Opponent (available for all builds) ──
            if (CustomMenu::g_menu.BeginSection("Disconnect"))
            {
                CustomMenu::g_menu.Combo("Reason", &g_dcReason, g_reasons, 14);
                if (CustomMenu::g_menu.ButtonColored("Kick Opponent", CustomMenu::Colors::Secondary, -1, 28))
                    rage::kick_opponent(g_dcReason);
                CustomMenu::g_menu.EndSection();
            }
        }

        // ===================== TAB 1: FUT =====================
        else if (tab == 1)
        {
            if (CustomMenu::g_menu.BeginSection("Division Rivals"))
            {
                CustomMenu::g_menu.StatusIndicator("System", division::IsReady());

                int prevDiv = division::selectedDivision;
                CustomMenu::g_menu.Combo("Division", &division::selectedDivision, g_divLabels, 13);
                if (division::selectedDivision != prevDiv)
                    division::UpdateValues(division::selectedDivision);

                if (division::IsReady())
                {
                    // Install hook button (one-time)
                    if (!division::IsHooked())
                    {
                        if (CustomMenu::g_menu.ButtonColored("Install Hook", CustomMenu::Colors::Primary, -1, 28))
                            division::InstallHook();
                    }
                    else
                    {
                        CustomMenu::g_menu.StatusIndicator("Hook Active", true);
                    }

                    // Apply button
                    if (division::IsHooked() && division::selectedDivision > 0)
                    {
                        if (CustomMenu::g_menu.ButtonColored("Apply Division", CustomMenu::Colors::Success, -1, 28))
                            division::Apply();
                    }

                    // Coop Rivals toggle
                    bool prevCoop = division::enableCoopRivals;
                    CustomMenu::g_menu.Toggle("Coop Rivals", &division::enableCoopRivals);
                    if (division::enableCoopRivals != prevCoop)
                        division::SetCoopRivals(division::enableCoopRivals);
                }
                else
                {
                    CustomMenu::g_menu.Label("Not initialized -- hook unavailable", CustomMenu::Colors::Warning);
                    if (CustomMenu::g_menu.Button("Retry Init##div", 120, 24))
                        division::Init(offsets::GameBase, offsets::GameSize);
                }

                CustomMenu::g_menu.EndSection();
            }

            if (CustomMenu::g_menu.BeginSection("FUT Champions"))
            {
                CustomMenu::g_menu.StatusIndicator("System", champions::IsReady());
                if (champions::IsReady())
                {
                    // Install Hook button (one-time)
                    if (!champions::IsHooked())
                    {
                        if (CustomMenu::g_menu.ButtonColored("Install Hook##champ", CustomMenu::Colors::Primary, -1, 28))
                            champions::InstallHook();
                    }
                    else
                    {
                        CustomMenu::g_menu.StatusIndicator("Hook Active", true);

                        CustomMenu::g_menu.Toggle("WL Score Spoofer", &champions::enabled,
                            "Spoof your WL record for easier matchmaking");
                        if (champions::enabled) {
#ifndef STANDARD_BUILD
                            CustomMenu::g_menu.SliderInt("Spoofed Wins", &champions::spoofedWins, 0, 15,
                                "Number of wins to spoof (0-15)");
                            CustomMenu::g_menu.SliderInt("Spoofed Losses", &champions::spoofedLosses, 0, 15,
                                "Number of losses to spoof (0-15)");
#else
                            CustomMenu::g_menu.Label("1W - 5L Fixed", CustomMenu::Colors::TextDisabled);
#endif
                        }
                    }
                }
                else
                {
                    CustomMenu::g_menu.Label("Not initialized", CustomMenu::Colors::Warning);
                    if (CustomMenu::g_menu.Button("Retry Init##champ", 120, 24))
                        champions::Init(offsets::GameBase, offsets::GameSize);
                }
                CustomMenu::g_menu.EndSection();
            }

            if (CustomMenu::g_menu.BeginSection("Draft & Packs"))
            {
                static bool draftModifier = false;
                static int draftRound = 1;
                CustomMenu::g_menu.Toggle("Draft Modifier", &draftModifier);
                if (draftModifier)
                    CustomMenu::g_menu.SliderInt("Draft Round", &draftRound, 1, 4);

                static bool skipPackAnim = false;
                CustomMenu::g_menu.Toggle("Skip Pack Animation", &skipPackAnim);

                static bool instantMoment = false;
                CustomMenu::g_menu.Toggle("Instant Moment", &instantMoment);

                CustomMenu::g_menu.Label("Requires hooks -- not yet active", CustomMenu::Colors::Warning);
                CustomMenu::g_menu.EndSection();
            }

            if (CustomMenu::g_menu.BeginSection("Matchmaking"))
            {
                static bool tournamentSpoofer = false;
                CustomMenu::g_menu.Toggle("Tournament Spoofer", &tournamentSpoofer);

                static bool matchTypeSpoof = false;
                CustomMenu::g_menu.Toggle("WL -> Draft Matchmaking", &matchTypeSpoof);

                static bool spoofEAID = false;
                CustomMenu::g_menu.Toggle("Spoof EAID", &spoofEAID);

                CustomMenu::g_menu.Label("Requires hooks -- not yet active", CustomMenu::Colors::Warning);
                CustomMenu::g_menu.EndSection();
            }
        }

#ifndef STANDARD_BUILD
        // ===================== TAB 2: Sliders (Premium only) =====================
        else if (tab == 2)
        {
            // ── Section 1: Quick Actions ──
            if (CustomMenu::g_menu.BeginSection("Quick Actions"))
            {
                CustomMenu::g_menu.BeginRow(2);

                if (hk_bind_applySliders) {
                    CustomMenu::g_menu.Label("Press key...", CustomMenu::Colors::Warning);
                    int nk = hk_applySliders;
                    if (menu::BindHotkeyPoll(nk, hk_bind_applySliders))
                        RebindSliderHotkey(hk_applySliders, nk, hk_do_applySliders);
                } else {
                    float btnW = 110;
                    if (CustomMenu::g_menu.ButtonColored("Apply Sliders V2", CustomMenu::Colors::Success, btnW, 28))
                        sliders::ApplySliders();
                    CustomMenu::g_menu.SameLine(btnW + 5);
                    char hkBuf[16]; fmt::snprintf(hkBuf, sizeof(hkBuf), "[%s]##hkas", menu::GetKeyName(hk_applySliders));
                    if (CustomMenu::g_menu.Button(hkBuf, 50, 28)) {
                        hk_bind_applySliders = true; menu::gIsBindingAnyHotkey = true;
                    }
                    CustomMenu::g_menu.EndSameLine(btnW + 5);
                }

                CustomMenu::g_menu.NextColumn();

                if (hk_bind_swapSettings) {
                    CustomMenu::g_menu.Label("Press key...", CustomMenu::Colors::Warning);
                    int nk = hk_swapSettings;
                    if (menu::BindHotkeyPoll(nk, hk_bind_swapSettings))
                        RebindSliderHotkey(hk_swapSettings, nk, hk_do_swapSettings);
                } else {
                    float btnW = 110;
                    if (CustomMenu::g_menu.ButtonColored("Swap Settings", CustomMenu::Colors::Warning, btnW, 28))
                        sliders::SwapSettings();
                    CustomMenu::g_menu.SameLine(btnW + 5);
                    char hkBuf[16]; fmt::snprintf(hkBuf, sizeof(hkBuf), "[%s]##hkss", menu::GetKeyName(hk_swapSettings));
                    if (CustomMenu::g_menu.Button(hkBuf, 50, 28)) {
                        hk_bind_swapSettings = true; menu::gIsBindingAnyHotkey = true;
                    }
                    CustomMenu::g_menu.EndSameLine(btnW + 5);
                }

                CustomMenu::g_menu.EndRow();

                CustomMenu::g_menu.BeginRow(2);
                if (CustomMenu::g_menu.ButtonColored("Refresh Names", CustomMenu::Colors::Primary, 150, 28)) {
                    sliders::RefreshPlayerNames();
                }
                CustomMenu::g_menu.NextColumn();
                CustomMenu::g_menu.EndRow();

                CustomMenu::g_menu.EndSection();
            }

            // ── Section 2: Player Selection ──
            if (CustomMenu::g_menu.BeginSection("Player Selection"))
            {
                CustomMenu::g_menu.Toggle("Player Selection Mode", &sliders::usePlayerSelection);

                if (!sliders::usePlayerSelection)
                {
                    CustomMenu::g_menu.Toggle("Apply to Opponent", &sliders::applyToOpponent);
                }
                else
                {
                    // Build team name labels (NoCRT safe)
                    char localLabel[80];
                    {
                        const char* prefix = "LOCAL: ";
                        int p = 0;
                        while (prefix[p]) { localLabel[p] = prefix[p]; p++; }
                        int n = 0;
                        while (sliders::teamNames[0][n] && p < 78) { localLabel[p++] = sliders::teamNames[0][n++]; }
                        localLabel[p] = '\0';
                    }
                    char oppLabel[80];
                    {
                        const char* prefix = "OPP: ";
                        int p = 0;
                        while (prefix[p]) { oppLabel[p] = prefix[p]; p++; }
                        int n = 0;
                        while (sliders::teamNames[1][n] && p < 78) { oppLabel[p++] = sliders::teamNames[1][n++]; }
                        oppLabel[p] = '\0';
                    }

                    CustomMenu::g_menu.BeginRow(2);
                    CustomMenu::g_menu.Label(localLabel, CustomMenu::Colors::Accent);
                    CustomMenu::g_menu.NextColumn();
                    CustomMenu::g_menu.Label(oppLabel, CustomMenu::Colors::Secondary);
                    CustomMenu::g_menu.EndRow();

                    CustomMenu::g_menu.BeginRow(2);
                    if (CustomMenu::g_menu.Button("All##L", 100, 24)) { sliders::SelectAll(0, true); }
                    if (CustomMenu::g_menu.Button("Clear##L", 100, 24)) { sliders::SelectAll(0, false); }
                    CustomMenu::g_menu.NextColumn();
                    if (CustomMenu::g_menu.Button("All##O", 100, 24)) { sliders::SelectAll(1, true); }
                    if (CustomMenu::g_menu.Button("Clear##O", 100, 24)) { sliders::SelectAll(1, false); }
                    CustomMenu::g_menu.EndRow();

                    // Player name toggles
                    int maxCount = sliders::playerCount[0] > sliders::playerCount[1]
                                 ? sliders::playerCount[0] : sliders::playerCount[1];
                    if (maxCount > sliders::MAX_PLAYERS) maxCount = sliders::MAX_PLAYERS;

                    for (int i = 0; i < maxCount; i++)
                    {
                        CustomMenu::g_menu.BeginRow(2);
                        if (i < sliders::playerCount[0]) {
                            CustomMenu::g_menu.Toggle(sliders::playerNames[0][i], &sliders::playerSelected[0][i]);
                        }
                        CustomMenu::g_menu.NextColumn();
                        if (i < sliders::playerCount[1]) {
                            CustomMenu::g_menu.Toggle(sliders::playerNames[1][i], &sliders::playerSelected[1][i]);
                        }
                        CustomMenu::g_menu.EndRow();
                    }
                }

                CustomMenu::g_menu.EndSection();
            }

            // ── Section 3: Local Sliders ──
            if (CustomMenu::g_menu.BeginSection("Local Sliders"))
            {
                CustomMenu::g_menu.SliderFloat("Acceleration##L",        &sliders::local_acceleration, 1.0f, 99.0f, "%.0f");
                CustomMenu::g_menu.SliderFloat("Sprint Speed##L",        &sliders::local_sprint, 1.0f, 99.0f, "%.0f");
                CustomMenu::g_menu.SliderFloat("Shoot Error##L",         &sliders::local_shoot_error, 1.0f, 99.0f, "%.0f");
                CustomMenu::g_menu.SliderFloat("Shoot Speed##L",         &sliders::local_shoot_speed, 1.0f, 99.0f, "%.0f");
                CustomMenu::g_menu.SliderFloat("Pass Error##L",          &sliders::local_pass_error, 1.0f, 99.0f, "%.0f");
                CustomMenu::g_menu.SliderFloat("Pass Speed##L",          &sliders::local_pass_speed, 1.0f, 99.0f, "%.0f");
                CustomMenu::g_menu.SliderFloat("First Touch Error##L",   &sliders::local_first_touch_error, 1.0f, 99.0f, "%.0f");
                CustomMenu::g_menu.SliderFloat("Header Shot Error##L",   &sliders::local_header_shot_error, 1.0f, 99.0f, "%.0f");
                CustomMenu::g_menu.SliderFloat("Header Pass Error##L",   &sliders::local_header_pass_error, 1.0f, 99.0f, "%.0f");
                CustomMenu::g_menu.SliderFloat("Intercept Error##L",     &sliders::local_intercept_error, 1.0f, 99.0f, "%.0f");
                CustomMenu::g_menu.SliderFloat("Ball Deflection##L",     &sliders::local_ball_deflection, 1.0f, 99.0f, "%.0f");
                CustomMenu::g_menu.SliderFloat("Marking##L",             &sliders::local_position_marking, 1.0f, 99.0f, "%.0f");
                CustomMenu::g_menu.SliderFloat("Line Length##L",         &sliders::local_position_line_length, 1.0f, 99.0f, "%.0f");
                CustomMenu::g_menu.SliderFloat("Line Width##L",          &sliders::local_position_line_width, 1.0f, 99.0f, "%.0f");
                CustomMenu::g_menu.SliderFloat("Def. Line Height##L",    &sliders::local_position_defensive_line_height, 1.0f, 99.0f, "%.0f");
                CustomMenu::g_menu.SliderFloat("Run Frequency##L",       &sliders::local_position_run_frequency, 1.0f, 99.0f, "%.0f");
                CustomMenu::g_menu.SliderFloat("Fullback Pos##L",        &sliders::local_position_fullback, 1.0f, 99.0f, "%.0f");
                CustomMenu::g_menu.SliderFloat("GK Ability##L",          &sliders::local_gk_ability, 1.0f, 99.0f, "%.0f");
                CustomMenu::g_menu.SliderFloat("Tackle Aggression##L",   &sliders::local_tackle_aggression, 1.0f, 99.0f, "%.0f");
                CustomMenu::g_menu.SliderFloat("Injury Severity##L",     &sliders::local_injury_severity, 1.0f, 99.0f, "%.0f");
                CustomMenu::g_menu.SliderFloat("Injury Frequency##L",    &sliders::local_injury_frequency, 1.0f, 99.0f, "%.0f");
                CustomMenu::g_menu.EndSection();
            }

            // ── Section 4: Opponent Sliders ──
            if (CustomMenu::g_menu.BeginSection("Opponent Sliders"))
            {
                CustomMenu::g_menu.SliderFloat("Acceleration##O",        &sliders::opp_acceleration, 1.0f, 99.0f, "%.0f");
                CustomMenu::g_menu.SliderFloat("Sprint Speed##O",        &sliders::opp_sprint, 1.0f, 99.0f, "%.0f");
                CustomMenu::g_menu.SliderFloat("Shoot Error##O",         &sliders::opp_shoot_error, 1.0f, 99.0f, "%.0f");
                CustomMenu::g_menu.SliderFloat("Shoot Speed##O",         &sliders::opp_shoot_speed, 1.0f, 99.0f, "%.0f");
                CustomMenu::g_menu.SliderFloat("Pass Error##O",          &sliders::opp_pass_error, 1.0f, 99.0f, "%.0f");
                CustomMenu::g_menu.SliderFloat("Pass Speed##O",          &sliders::opp_pass_speed, 1.0f, 99.0f, "%.0f");
                CustomMenu::g_menu.SliderFloat("First Touch Error##O",   &sliders::opp_first_touch_error, 1.0f, 99.0f, "%.0f");
                CustomMenu::g_menu.SliderFloat("Header Shot Error##O",   &sliders::opp_header_shot_error, 1.0f, 99.0f, "%.0f");
                CustomMenu::g_menu.SliderFloat("Header Pass Error##O",   &sliders::opp_header_pass_error, 1.0f, 99.0f, "%.0f");
                CustomMenu::g_menu.SliderFloat("Intercept Error##O",     &sliders::opp_intercept_error, 1.0f, 99.0f, "%.0f");
                CustomMenu::g_menu.SliderFloat("Ball Deflection##O",     &sliders::opp_ball_deflection, 1.0f, 99.0f, "%.0f");
                CustomMenu::g_menu.SliderFloat("Marking##O",             &sliders::opp_position_marking, 1.0f, 99.0f, "%.0f");
                CustomMenu::g_menu.SliderFloat("Line Length##O",         &sliders::opp_position_line_length, 1.0f, 99.0f, "%.0f");
                CustomMenu::g_menu.SliderFloat("Line Width##O",          &sliders::opp_position_line_width, 1.0f, 99.0f, "%.0f");
                CustomMenu::g_menu.SliderFloat("Def. Line Height##O",    &sliders::opp_position_defensive_line_height, 1.0f, 99.0f, "%.0f");
                CustomMenu::g_menu.SliderFloat("Run Frequency##O",       &sliders::opp_position_run_frequency, 1.0f, 99.0f, "%.0f");
                CustomMenu::g_menu.SliderFloat("Fullback Pos##O",        &sliders::opp_position_fullback, 1.0f, 99.0f, "%.0f");
                CustomMenu::g_menu.SliderFloat("GK Ability##O",          &sliders::opp_gk_ability, 1.0f, 99.0f, "%.0f");
                CustomMenu::g_menu.SliderFloat("Tackle Aggression##O",   &sliders::opp_tackle_aggression, 1.0f, 99.0f, "%.0f");
                CustomMenu::g_menu.SliderFloat("Injury Severity##O",     &sliders::opp_injury_severity, 1.0f, 99.0f, "%.0f");
                CustomMenu::g_menu.SliderFloat("Injury Frequency##O",    &sliders::opp_injury_frequency, 1.0f, 99.0f, "%.0f");
                CustomMenu::g_menu.EndSection();
            }
        }

        // ===================== TAB 3: Rage (Premium only) =====================
        else if (tab == 3)
        {
            if (CustomMenu::g_menu.BeginSection("Opponent Control"))
            {
                // Row 1: Crash + Slider Bomb
                CustomMenu::g_menu.BeginRow(2);

                if (hk_bind_crash) {
                    CustomMenu::g_menu.Label("Press key...", CustomMenu::Colors::Warning);
                    int nk = hk_crash;
                    if (menu::BindHotkeyPoll(nk, hk_bind_crash))
                        RebindRageHotkey(hk_crash, nk, hk_do_crash);
                } else {
                    float btnW = 110;
                    if (CustomMenu::g_menu.ButtonColored("Crash Opponent", CustomMenu::Colors::Secondary, btnW, 28))
                        rage::crash_opps();
                    CustomMenu::g_menu.SameLine(btnW + 5);
                    char hkBuf[16]; fmt::snprintf(hkBuf, sizeof(hkBuf), "[%s]##hkc", menu::GetKeyName(hk_crash));
                    if (CustomMenu::g_menu.Button(hkBuf, 50, 28)) {
                        hk_bind_crash = true; menu::gIsBindingAnyHotkey = true;
                    }
                    CustomMenu::g_menu.EndSameLine(btnW + 5);
                }

                CustomMenu::g_menu.NextColumn();

                if (hk_bind_slider) {
                    CustomMenu::g_menu.Label("Press key...", CustomMenu::Colors::Warning);
                    int nk = hk_slider;
                    if (menu::BindHotkeyPoll(nk, hk_bind_slider))
                        RebindRageHotkey(hk_slider, nk, hk_do_slider);
                } else {
                    float btnW = 110;
                    if (CustomMenu::g_menu.ButtonColored("SLIDER BOMB", CustomMenu::Colors::Secondary, btnW, 28))
                        rage::slider_bomb();
                    CustomMenu::g_menu.SameLine(btnW + 5);
                    char hkBuf[16]; fmt::snprintf(hkBuf, sizeof(hkBuf), "[%s]##hks", menu::GetKeyName(hk_slider));
                    if (CustomMenu::g_menu.Button(hkBuf, 50, 28)) {
                        hk_bind_slider = true; menu::gIsBindingAnyHotkey = true;
                    }
                    CustomMenu::g_menu.EndSameLine(btnW + 5);
                }

                CustomMenu::g_menu.EndRow();

                // Row 2: Freeze 1 + Freeze 2
                CustomMenu::g_menu.BeginRow(2);

                if (hk_bind_freeze1) {
                    CustomMenu::g_menu.Label("Press key...", CustomMenu::Colors::Warning);
                    int nk = hk_freeze1;
                    if (menu::BindHotkeyPoll(nk, hk_bind_freeze1))
                        RebindRageHotkey(hk_freeze1, nk, hk_do_freeze1);
                } else {
                    float btnW = 110;
                    if (CustomMenu::g_menu.ButtonColored("Freeze 1", CustomMenu::Colors::Warning, btnW, 28))
                        rage::pause_op_game();
                    CustomMenu::g_menu.SameLine(btnW + 5);
                    char hkBuf[16]; fmt::snprintf(hkBuf, sizeof(hkBuf), "[%s]##hkf1", menu::GetKeyName(hk_freeze1));
                    if (CustomMenu::g_menu.Button(hkBuf, 50, 28)) {
                        hk_bind_freeze1 = true; menu::gIsBindingAnyHotkey = true;
                    }
                    CustomMenu::g_menu.EndSameLine(btnW + 5);
                }

                CustomMenu::g_menu.NextColumn();

                if (hk_bind_freeze2) {
                    CustomMenu::g_menu.Label("Press key...", CustomMenu::Colors::Warning);
                    int nk = hk_freeze2;
                    if (menu::BindHotkeyPoll(nk, hk_bind_freeze2))
                        RebindRageHotkey(hk_freeze2, nk, hk_do_freeze2);
                } else {
                    float btnW = 110;
                    if (CustomMenu::g_menu.ButtonColored("Freeze 2", CustomMenu::Colors::Warning, btnW, 28))
                        rage::pause_op_game_new();
                    CustomMenu::g_menu.SameLine(btnW + 5);
                    char hkBuf[16]; fmt::snprintf(hkBuf, sizeof(hkBuf), "[%s]##hkf2", menu::GetKeyName(hk_freeze2));
                    if (CustomMenu::g_menu.Button(hkBuf, 50, 28)) {
                        hk_bind_freeze2 = true; menu::gIsBindingAnyHotkey = true;
                    }
                    CustomMenu::g_menu.EndSameLine(btnW + 5);
                }

                CustomMenu::g_menu.EndRow();
                CustomMenu::g_menu.EndSection();
            }

            if (CustomMenu::g_menu.BeginSection("Disconnect"))
            {
                CustomMenu::g_menu.Combo("Reason", &g_dcReason, g_reasons, 14);

                if (hk_bind_kick) {
                    CustomMenu::g_menu.Label("Press key...", CustomMenu::Colors::Warning);
                    int nk = hk_kick;
                    if (menu::BindHotkeyPoll(nk, hk_bind_kick))
                        RebindRageHotkey(hk_kick, nk, hk_do_kick);
                } else {
                    float btnW = 200;
                    if (CustomMenu::g_menu.ButtonColored("Kick Opponent", CustomMenu::Colors::Secondary, btnW, 28))
                        rage::kick_opponent(g_dcReason);
                    CustomMenu::g_menu.SameLine(btnW + 5);
                    char hkBuf[16]; fmt::snprintf(hkBuf, sizeof(hkBuf), "[%s]##hkk", menu::GetKeyName(hk_kick));
                    if (CustomMenu::g_menu.Button(hkBuf, 50, 28)) {
                        hk_bind_kick = true; menu::gIsBindingAnyHotkey = true;
                    }
                    CustomMenu::g_menu.EndSameLine(btnW + 5);
                }

                if (CustomMenu::g_menu.ButtonColored("Change Team", CustomMenu::Colors::Primary, -1, 28)) {
                    toast::Show(toast::Type::Info, "Change team (needs hook)");
                }
                CustomMenu::g_menu.EndSection();
            }

            if (CustomMenu::g_menu.BeginSection("Sleep Opponent"))
            {
                static bool sleepOpponent = false;
                static bool bypassSleep = false;
                CustomMenu::g_menu.Toggle("Sleep Opponent", &sleepOpponent);
                if (sleepOpponent)
                    CustomMenu::g_menu.Label("Does NOT work in Rivals!", CustomMenu::Colors::Warning);
                CustomMenu::g_menu.Toggle("Bypass Sleep", &bypassSleep);
                CustomMenu::g_menu.Label("Requires hook -- not yet active", CustomMenu::Colors::Warning);
                CustomMenu::g_menu.EndSection();
            }

            if (!g_rageReady) {
                CustomMenu::g_menu.Label("WARNING: Rage offsets not found!", CustomMenu::Colors::Warning);
            }
        }
#endif // !STANDARD_BUILD

        // ===================== TAB 4: AI =====================
        else if (tab == 4)
        {
#ifndef STANDARD_BUILD
            if (CustomMenu::g_menu.BeginSection("AI Control"))
            {
                CustomMenu::g_menu.Toggle("AI vs Opponents", &g_aiVsOpps,
                    "Take control of AI teammates to attack opponents");
                CustomMenu::g_menu.Toggle("Disable Opponent AI", &g_disableAi,
                    "Remove AI control from opponent team");
                CustomMenu::g_menu.EndSection();
            }
#endif

            if (CustomMenu::g_menu.BeginSection("AI Difficulty"))
            {
#ifndef STANDARD_BUILD
                CustomMenu::g_menu.Toggle("AI Local Legendary",
                    &ai_difficulty::g_localLegendary,
                    "Sets your AI to legendary difficulty at kickoff");
                CustomMenu::g_menu.Toggle("AI Opponent Beginner",
                    &ai_difficulty::g_opponentBeginner,
                    "Sets opponent AI to beginner difficulty at kickoff");
#else
                CustomMenu::g_menu.Label("AI Local Legendary", CustomMenu::Colors::TextDisabled);
                CustomMenu::g_menu.Label("AI Opponent Beginner", CustomMenu::Colors::TextDisabled);
                CustomMenu::g_menu.Label("Premium feature", CustomMenu::Colors::Warning);
#endif
                CustomMenu::g_menu.EndSection();
            }
        }

        // ===================== TAB 5: Squad Battles =====================
        else if (tab == 5)
        {
            if (CustomMenu::g_menu.BeginSection("Difficulty"))
            {
                static int sbDifficulty = 0;
                CustomMenu::g_menu.Combo("Difficulty", &sbDifficulty, g_difficulties, 7);
                CustomMenu::g_menu.Label("Requires hooks -- not yet active", CustomMenu::Colors::Warning);
                CustomMenu::g_menu.EndSection();
            }

            if (CustomMenu::g_menu.BeginSection("Match Timer"))
            {
                static bool freezeTimer = false;
                CustomMenu::g_menu.Toggle("Freeze Timer", &freezeTimer);
                CustomMenu::g_menu.Label("Requires hooks -- not yet active", CustomMenu::Colors::Warning);
                CustomMenu::g_menu.EndSection();
            }

            if (CustomMenu::g_menu.BeginSection("Ball Control"))
            {
                static bool magnetBall = false;
                CustomMenu::g_menu.Toggle("Magnet Ball", &magnetBall);
                CustomMenu::g_menu.Label("Requires hooks -- not yet active", CustomMenu::Colors::Warning);
                CustomMenu::g_menu.EndSection();
            }
        }

        // ===================== TAB 6: Pro Club =====================
        else if (tab == 6)
        {
            if (CustomMenu::g_menu.BeginSection("Pro Club Features"))
            {
                static bool unlockAll = false;
                static bool xpBoost = false;
                static bool skills99 = false;
                static bool botFiveStars = false;
                static bool aiAutoPlay = false;
                static bool proFreeFacilities = false;
                static bool proSearchAlone = false;
                CustomMenu::g_menu.Toggle("Unlock All", &unlockAll);
                CustomMenu::g_menu.Toggle("XP Boost", &xpBoost);
                CustomMenu::g_menu.Toggle("Skills 99", &skills99);
                CustomMenu::g_menu.Toggle("Bot 5 Stars", &botFiveStars);
                CustomMenu::g_menu.Toggle("AI Auto Play", &aiAutoPlay);
                CustomMenu::g_menu.Toggle("Free Facilities", &proFreeFacilities);
                CustomMenu::g_menu.Toggle("Search Game Alone", &proSearchAlone);
                CustomMenu::g_menu.EndSection();
            }

            if (CustomMenu::g_menu.BeginSection("AI Playstyles"))
            {
                CustomMenu::g_menu.Label("Must be captain", CustomMenu::Colors::Warning);
                static int aiPlaystyle = 0;
                CustomMenu::g_menu.Combo("AI Playstyle", &aiPlaystyle, g_playstyles, 3);
                CustomMenu::g_menu.EndSection();
            }

            if (CustomMenu::g_menu.BeginSection("Player Playstyles"))
            {
                CustomMenu::g_menu.Label("Must be captain", CustomMenu::Colors::Warning);
                static int playerPlaystyle = 0;
                CustomMenu::g_menu.Combo("Your Playstyle", &playerPlaystyle, g_playstyles2, 3);
                CustomMenu::g_menu.EndSection();
            }
        }

        // ===================== TAB 7: Misc =====================
        else if (tab == 7)
        {
            if (CustomMenu::g_menu.BeginSection("Camera Settings"))
            {
                CustomMenu::g_menu.Label("Requires hooks -- not yet active", CustomMenu::Colors::Warning);
                CustomMenu::g_menu.EndSection();
            }

#ifndef STANDARD_BUILD
            if (CustomMenu::g_menu.BeginSection("Hotkeys"))
            {
                // Crash
                if (hk_bind_crash) {
                    CustomMenu::g_menu.Label("Press key for Crash...", CustomMenu::Colors::Warning);
                    int nk = hk_crash;
                    if (menu::BindHotkeyPoll(nk, hk_bind_crash))
                        RebindRageHotkey(hk_crash, nk, hk_do_crash);
                } else {
                    char hkBuf[32]; fmt::snprintf(hkBuf, sizeof(hkBuf), "Crash [%s]", menu::GetKeyName(hk_crash));
                    if (CustomMenu::g_menu.Button(hkBuf, 200, 28))
                        { hk_bind_crash = true; menu::gIsBindingAnyHotkey = true; }
                }

                // Freeze 1
                if (hk_bind_freeze1) {
                    CustomMenu::g_menu.Label("Press key for Freeze 1...", CustomMenu::Colors::Warning);
                    int nk = hk_freeze1;
                    if (menu::BindHotkeyPoll(nk, hk_bind_freeze1))
                        RebindRageHotkey(hk_freeze1, nk, hk_do_freeze1);
                } else {
                    char hkBuf[32]; fmt::snprintf(hkBuf, sizeof(hkBuf), "Freeze 1 [%s]", menu::GetKeyName(hk_freeze1));
                    if (CustomMenu::g_menu.Button(hkBuf, 200, 28))
                        { hk_bind_freeze1 = true; menu::gIsBindingAnyHotkey = true; }
                }

                // Freeze 2
                if (hk_bind_freeze2) {
                    CustomMenu::g_menu.Label("Press key for Freeze 2...", CustomMenu::Colors::Warning);
                    int nk = hk_freeze2;
                    if (menu::BindHotkeyPoll(nk, hk_bind_freeze2))
                        RebindRageHotkey(hk_freeze2, nk, hk_do_freeze2);
                } else {
                    char hkBuf[32]; fmt::snprintf(hkBuf, sizeof(hkBuf), "Freeze 2 [%s]", menu::GetKeyName(hk_freeze2));
                    if (CustomMenu::g_menu.Button(hkBuf, 200, 28))
                        { hk_bind_freeze2 = true; menu::gIsBindingAnyHotkey = true; }
                }

                // Slider Bomb
                if (hk_bind_slider) {
                    CustomMenu::g_menu.Label("Press key for Slider Bomb...", CustomMenu::Colors::Warning);
                    int nk = hk_slider;
                    if (menu::BindHotkeyPoll(nk, hk_bind_slider))
                        RebindRageHotkey(hk_slider, nk, hk_do_slider);
                } else {
                    char hkBuf[32]; fmt::snprintf(hkBuf, sizeof(hkBuf), "Slider Bomb [%s]", menu::GetKeyName(hk_slider));
                    if (CustomMenu::g_menu.Button(hkBuf, 200, 28))
                        { hk_bind_slider = true; menu::gIsBindingAnyHotkey = true; }
                }

                // Kick
                if (hk_bind_kick) {
                    CustomMenu::g_menu.Label("Press key for Kick...", CustomMenu::Colors::Warning);
                    int nk = hk_kick;
                    if (menu::BindHotkeyPoll(nk, hk_bind_kick))
                        RebindRageHotkey(hk_kick, nk, hk_do_kick);
                } else {
                    char hkBuf[32]; fmt::snprintf(hkBuf, sizeof(hkBuf), "Kick [%s]", menu::GetKeyName(hk_kick));
                    if (CustomMenu::g_menu.Button(hkBuf, 200, 28))
                        { hk_bind_kick = true; menu::gIsBindingAnyHotkey = true; }
                }

                CustomMenu::g_menu.EndSection();
            }
#endif
        }

        // ===================== TAB 8: Server =====================
        else if (tab == 8)
        {
            if (!server::IsReady())
            {
                if (CustomMenu::g_menu.BeginSection("Server"))
                {
                    CustomMenu::g_menu.Label("Server system not initialized", CustomMenu::Colors::Warning);
                    CustomMenu::g_menu.Label("Pattern scans may have failed — check log", CustomMenu::Colors::TextSecondary);
                    if (CustomMenu::g_menu.Button("Retry Init", 120, 28))
                        server::Init(offsets::GameBase, offsets::GameSize);
                    CustomMenu::g_menu.EndSection();
                }
            }
            else
            {
            if (CustomMenu::g_menu.BeginSection("Server Status"))
            {
                CustomMenu::g_menu.StatusIndicator("System", server::IsReady());
                CustomMenu::g_menu.StatusIndicator("Connected", server::connected);

                char curBuf[128];
                fmt::snprintf(curBuf, sizeof(curBuf), "Current: %s",
                    server::currentPingSite[0] ? server::currentPingSite : "N/A");
                CustomMenu::g_menu.Label(curBuf, CustomMenu::Colors::TextSecondary);

                if (server::enableOverride) {
                    char forcedBuf[128];
                    fmt::snprintf(forcedBuf, sizeof(forcedBuf), "Forced: %s", server::forcedPingSite);
                    CustomMenu::g_menu.Label(forcedBuf, CustomMenu::Colors::Success);
                }
                CustomMenu::g_menu.EndSection();
            }

            if (CustomMenu::g_menu.BeginSection("Server Selection"))
            {
                if (server::regionCount > 0)
                {
                    static const char* labels[server::MAX_REGIONS];
                    for (int i = 0; i < server::regionCount && i < server::MAX_REGIONS; i++)
                        labels[i] = server::GetRegionLabel(i);

                    CustomMenu::g_menu.Combo("Region", &server::selectedRegion, labels, server::regionCount);

                    CustomMenu::g_menu.BeginRow(2);
                    if (CustomMenu::g_menu.ButtonColored("Apply", CustomMenu::Colors::Success, 120, 28)) {
                        if (server::selectedRegion >= 0 && server::selectedRegion < server::regionCount) {
                            server::SetForcedPingSite(server::regions[server::selectedRegion].sites[0]);
                        }
                    }
                    CustomMenu::g_menu.NextColumn();
                    if (CustomMenu::g_menu.ButtonColored("Restore", CustomMenu::Colors::Warning, 120, 28)) {
                        server::RestorePingSite();
                    }
                    CustomMenu::g_menu.EndRow();
                }
                else
                {
                    CustomMenu::g_menu.Label("No regions loaded", CustomMenu::Colors::Warning);
                    if (CustomMenu::g_menu.Button("Enumerate Regions", 160, 28))
                        server::EnumerateRegions();
                }
                CustomMenu::g_menu.EndSection();
            }

            if (CustomMenu::g_menu.BeginSection("Connection"))
            {
                CustomMenu::g_menu.BeginRow(3);
                if (CustomMenu::g_menu.Button("Refresh", 90, 28))
                    server::RefreshCurrentPingSite();
                CustomMenu::g_menu.NextColumn();
                if (CustomMenu::g_menu.ButtonColored("Disconnect", CustomMenu::Colors::Secondary, 90, 28))
                    server::Disconnect();
                CustomMenu::g_menu.NextColumn();
                if (CustomMenu::g_menu.ButtonColored("Reconnect", CustomMenu::Colors::Primary, 90, 28))
                    server::Reconnect();
                CustomMenu::g_menu.EndRow();
                CustomMenu::g_menu.EndSection();
            }
            } // end else (IsReady)
        }

        // ===================== TAB 9: Settings =====================
        else if (tab == 9)
        {
            if (CustomMenu::g_menu.BeginSection("Menu"))
            {
                CustomMenu::g_menu.SliderFloat("Opacity", &menu::menuOpacity, 0.1f, 1.0f);
                CustomMenu::g_menu.SetOpacity(menu::menuOpacity);
                static bool showNotifications = true;
                CustomMenu::g_menu.Toggle("Show Notifications", &showNotifications);
                CustomMenu::g_menu.EndSection();
            }
        }

        CustomMenu::g_menu.EndWindow();
    }

    // ── Opponent Info floating window (between EndWindow and EndFrame) ──
    if (opp_info::IsHooked() && opp_info::g_showWindow)
    {
        if (CustomMenu::g_menu.BeginFloatingWindow("Opponent Intel",
                screenW - 400, 20, 380, 460, &opp_info::g_showWindow))
        {
            if (!opp_info::g_opponent.valid)
            {
                CustomMenu::g_menu.Label("Waiting for match...", CustomMenu::Colors::TextSecondary);
            }
            else
            {
            // Snapshot the data to avoid race condition with detour thread
            opp_info::PlayerData snap;
            __movsb((unsigned char*)&snap, (const unsigned char*)&opp_info::g_opponent, sizeof(snap));

            // Force null-termination on all strings (prevent runaway %s)
            snap.name[sizeof(snap.name) - 1] = '\0';
            snap.platform[sizeof(snap.platform) - 1] = '\0';
            snap.clubName[sizeof(snap.clubName) - 1] = '\0';
            snap.clubTag[sizeof(snap.clubTag) - 1] = '\0';

            char line[128];

            CustomMenu::g_menu.LabelValue("Name", snap.name);
            CustomMenu::g_menu.LabelValue("Platform", snap.platform);

            if (snap.personaId) {
                fmt::snprintf(line, sizeof(line), "%llu", snap.personaId);
                CustomMenu::g_menu.LabelValue("Persona ID", line);
            }

            // Only show stats if they look sane (skip garbage values)
            if (snap.drRating > 0 && snap.drRating <= 99) {
                fmt::snprintf(line, sizeof(line), "%d", snap.drRating);
                CustomMenu::g_menu.LabelValue("DR Rating", line);
            }
            if (snap.chemistry > 0 && snap.chemistry <= 33) {
                fmt::snprintf(line, sizeof(line), "%d/33", snap.chemistry);
                CustomMenu::g_menu.LabelValue("Chemistry", line);
            }
            if (snap.teamOvr > 0 && snap.teamOvr <= 99) {
                fmt::snprintf(line, sizeof(line), "%d", snap.teamOvr);
                CustomMenu::g_menu.LabelValue("Team OVR", line);
            }
            if (snap.skillRating > 0 && snap.skillRating < 10000) {
                fmt::snprintf(line, sizeof(line), "%d", snap.skillRating);
                CustomMenu::g_menu.LabelValue("Skill Rating", line);
            }

            if (snap.seasonWins >= 0 && snap.seasonWins < 10000
                && snap.seasonLosses >= 0 && snap.seasonLosses < 10000
                && snap.seasonTies >= 0 && snap.seasonTies < 10000) {
                fmt::snprintf(line, sizeof(line), "%dW %dL %dD",
                    snap.seasonWins, snap.seasonLosses, snap.seasonTies);
                CustomMenu::g_menu.LabelValue("Record", line);
            }

            if (snap.dnfPercent > 0 && snap.dnfPercent <= 100) {
                fmt::snprintf(line, sizeof(line), "%d%%", snap.dnfPercent);
                CustomMenu::g_menu.LabelValue("DNF", line);
            }

            if (snap.creationYear > 2000 && snap.creationYear < 2030
                && snap.creationMonth >= 1 && snap.creationMonth <= 12) {
                static const char* months[] = {
                    "?","Jan","Feb","Mar","Apr","May","Jun",
                    "Jul","Aug","Sep","Oct","Nov","Dec"
                };
                fmt::snprintf(line, sizeof(line), "%s %u",
                    months[snap.creationMonth], snap.creationYear);
                CustomMenu::g_menu.LabelValue("Created", line);
            }

            if (snap.clubName[0] && snap.clubName[0] > 0x20 && snap.clubName[0] < 0x7F) {
                fmt::snprintf(line, sizeof(line), "%.30s [%.15s]",
                    snap.clubName, snap.clubTag);
                CustomMenu::g_menu.LabelValue("Club", line);
            }
            } // end if (valid)

            CustomMenu::g_menu.EndFloatingWindow();
        }
    }

    CustomMenu::g_menu.EndFrame();

    // ── Per-frame features (run even when menu is closed) ──
    if (g_rageReady && rage::slider_ptr)
    {
        __try {
            uintptr_t base = *(uintptr_t*)rage::slider_ptr;
            if (base)
            {
                // Anti-AFK: max out OSDK idle detection thresholds
                // Chain: slider -> +0x1080 -> +0x130 = OSDK match engine
                // +0x4CA4 = OSDK_TRANSITION_TO_IDLE_TIME  (DWORD, ms)
                // +0x4CA8 = OSDK_IDLE_DISCONNECT_TIME     (DWORD, ms)
                // +0x4CAC = OSDK_MAX_IDLES_ALLOWED        (DWORD)
                if (g_bypassAFK)
                {
                    uintptr_t p1 = *(uintptr_t*)(base + 0x1080);
                    if (p1) {
                        uintptr_t p2 = *(uintptr_t*)(p1 + 0x130);
                        if (p2) {
                            DWORD* transitionTime = (DWORD*)(p2 + 0x4CA4);
                            DWORD* disconnectTime = (DWORD*)(p2 + 0x4CA8);
                            DWORD* maxIdles       = (DWORD*)(p2 + 0x4CAC);
                            if (*transitionTime != 0x7FFFFFFF)
                                *transitionTime = 0x7FFFFFFF;
                            if (*disconnectTime != 0x7FFFFFFF)
                                *disconnectTime = 0x7FFFFFFF;
                            if (*maxIdles != 0x7FFFFFFF)
                                *maxIdles = 0x7FFFFFFF;
                        }
                    }
                }

                // No Loss: write 0x19 to match result
                if (g_noLoss)
                    *(unsigned int*)(base + 0x1A0) = 0x19;

                // Foul Control (WIP — disabled for now)
                // if (g_noFouls)
                //     *(unsigned char*)(base + 0xDF0) = 0;
                // if (g_noHandball)
                //     *(unsigned char*)(base + 0xDF1) = 0;
                // if (g_noBooking)
                //     *(unsigned char*)(base + 0xDF2) = 0;
                // if (g_noOffside)
                //     *(unsigned char*)(base + 0xDF6) = 1;
            }
        } __except(1) {}
    }

    // ── AI vs Opponents: send player control assignment every ~3 seconds ──
    static DWORD lastAiSend = 0;
    if (g_aiVsOpps && g_rageReady && rage::slider_ptr)
    {
        DWORD now = GetTickCount();
        if (now - lastAiSend > 3000) {
            lastAiSend = now;
            __try {
                uintptr_t rcx = 0; rage::dispatch_fn_t fn = nullptr;
                if (rage::get_dispatch(rcx, fn)) {
                    uint64_t opcode = 0xA2CB726E;
                    int ourSide = sliders::playerside;

                    for (int i = 2; i < 12; i++) {
                        unsigned int buffer[3] = { (unsigned int)ourSide, (unsigned int)i, 0 };

                        hook::g_allow_attack_send = true;
                        spoof_call(fn, (uint64_t)rcx,
                            (uint64_t*)&opcode, (uint64_t*)&opcode,
                            (void*)buffer, (int)12, (char)0xFF, (unsigned char)0);
                        hook::g_allow_attack_send = false;
                    }
                }
            } __except(1) {}
        }
    }

    // ── Disable Opponent AI: send control assignment for opponent team ──
    static DWORD lastDisableAiSend = 0;
    if (g_disableAi && g_rageReady && rage::slider_ptr)
    {
        DWORD now2 = GetTickCount();
        if (now2 - lastDisableAiSend > 3000) {
            lastDisableAiSend = now2;
            __try {
                uintptr_t rcx = 0; rage::dispatch_fn_t fn = nullptr;
                if (rage::get_dispatch(rcx, fn)) {
                    uint64_t opcode = 0xA2CB726E;
                    int oppSide = (sliders::playerside == 0) ? 1 : 0;

                    for (int i = 2; i < 12; i++) {
                        unsigned int buffer[3] = { (unsigned int)oppSide, (unsigned int)i, 0 };

                        hook::g_allow_attack_send = true;
                        spoof_call(fn, (uint64_t)rcx,
                            (uint64_t*)&opcode, (uint64_t*)&opcode,
                            (void*)buffer, (int)12, (char)0xFF, (unsigned char)0);
                        hook::g_allow_attack_send = false;
                    }
                }
            } __except(1) {}
        }
    }

    // ── Toast notifications (always rendered, even if menu is closed) ──
    if (g_rendererPtr) {
        LARGE_INTEGER now;
        QueryPerformanceCounter(&now);
        float dt = (float)(now.QuadPart - g_lastTime.QuadPart) / (float)g_freq.QuadPart;
        g_lastTime = now;
        if (dt > 0.1f) dt = 0.1f;  // clamp to avoid jumps
        toast::Render(*g_rendererPtr, screenW, screenH, dt);
    }

    if (s_first) { log::debug("[OVL] Done\r\n"); s_first = false; }
}
