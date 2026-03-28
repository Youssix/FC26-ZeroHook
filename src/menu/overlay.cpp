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

    // Kick reason (shared between menu button and hotkey)
    int  g_dcReason = 0;

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

    // ── Hotkeys for both builds ──
    int  hk_applySliders = VK_F5;
    int  hk_swapSettings = VK_F7;
    bool hk_bind_applySliders = false;
    bool hk_bind_swapSettings = false;

    void hk_do_applySliders() { sliders::ApplySliders(); }
    void hk_do_swapSettings() { sliders::SwapSettings(); }

    void RegisterCommonHotkeys()
    {
        menu::RegisterHotkey(hk_applySliders, hk_do_applySliders);
        menu::RegisterHotkey(hk_swapSettings, hk_do_swapSettings);
    }

    void RebindCommonHotkey(int& hkVar, int newKey, void(*action)())
    {
        menu::UnregisterHotkey(hkVar);
        hkVar = newKey;
        menu::RegisterHotkey(newKey, action);
    }

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
    g_rendererPtr = renderer;
    CustomMenu::g_menu.Init(renderer);
    CustomMenu::g_menu.SetOpen(true);

    // Only do one-time game init on first call — resizes only need renderer re-init
    static bool s_gameInitDone = false;
    if (!s_gameInitDone)
    {
        FrostbiteInput::Init();

        // Scan rage + slider offsets (pattern scan needs game module)
        if (offsets::GameBase && offsets::GameSize)
        {
            g_rageReady = rage::InitOffsets(offsets::GameBase, offsets::GameSize);
            sliders::InitOffsets(offsets::GameBase, offsets::GameSize);
            // competitive::Init(offsets::GameBase, offsets::GameSize);  // WIP
            // dda::Init(offsets::GameBase, offsets::GameSize);          // WIP
            server::Init(offsets::GameBase, offsets::GameSize);
            champions::Init(offsets::GameBase, offsets::GameSize);
            division::Init(offsets::GameBase, offsets::GameSize);
        }

        QueryPerformanceFrequency(&g_freq);
        QueryPerformanceCounter(&g_lastTime);

        RegisterCommonHotkeys();
#ifndef STANDARD_BUILD
        if (g_rageReady)
            RegisterRageHotkeys();
#endif

        s_gameInitDone = true;
    }

    g_initialized = true;
}

bool overlay::IsInitialized()
{
    return g_initialized;
}

void overlay::Frame(float screenW, float screenH)
{
    static bool s_first = true;

    if (s_first) log::to_file("[OVL] BlockInput(false)\r\n");
    FrostbiteInput::BlockGameInput(false);

    if (s_first) log::to_file("[OVL] CheckHotkeys\r\n");
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

    if (s_first) log::to_file("[OVL] GetMouse\r\n");
    float mouseX   = (float)FrostbiteInput::GetMouseX();
    float mouseY   = (float)FrostbiteInput::GetMouseY();
    bool  mouseDown = FrostbiteInput::IsMouseButtonDown(0);
    float scroll   = (float)FrostbiteInput::GetMouseScroll();

    if (s_first) log::to_file("[OVL] ReBlock\r\n");
    FrostbiteInput::BlockGameInput(
        CustomMenu::g_menu.IsOpen() && CustomMenu::g_menu.WantsMouse());

    if (s_first) log::to_file("[OVL] BeginFrame\r\n");
    CustomMenu::g_menu.SetScrollInput(scroll);
    CustomMenu::g_menu.BeginFrame(screenW, screenH, mouseX, mouseY, mouseDown, scroll);

    if (s_first) log::to_file("[OVL] BeginWindow\r\n");
    if (CustomMenu::g_menu.BeginWindow("Ring-1"))
    {
        // ── Sidebar tabs ──
        CustomMenu::g_menu.BeginTabs();
        CustomMenu::g_menu.Tab("General",       0);
        CustomMenu::g_menu.Tab("FUT",           1);
        CustomMenu::g_menu.Tab("Sliders",       2);
#ifndef STANDARD_BUILD
        CustomMenu::g_menu.Tab("Rage",          3);
#else
        CustomMenu::g_menu.TabDisabled("Rage",  3);
#endif
        CustomMenu::g_menu.Tab("AI",            4);
        CustomMenu::g_menu.Tab("Squad Battles", 5);
        CustomMenu::g_menu.Tab("Pro Club",      6);
        CustomMenu::g_menu.Tab("Misc",          7);
        CustomMenu::g_menu.Tab("Server",        8);
        CustomMenu::g_menu.Tab("Settings",      9);
        CustomMenu::g_menu.EndTabs();

        int tab = CustomMenu::g_menu.GetSelectedTab();

        // Crash diagnostic: verbose logging on tab switch frame
        static int s_lastLoggedTab = -1;
        bool s_tabSwitchFrame = (tab != s_lastLoggedTab);
        overlay::s_tabSwitchFrame = s_tabSwitchFrame;
        if (s_tabSwitchFrame) {
            char tbuf[64];
            fmt::snprintf(tbuf, sizeof(tbuf), "[OVL] Rendering tab %d\r\n", tab);
            log::to_file(tbuf);
            s_lastLoggedTab = tab;
        }

        __try {

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

            // ── Match Utilities ──
            if (CustomMenu::g_menu.BeginSection("Match Utilities"))
            {
                CustomMenu::g_menu.Toggle("Bypass Alt Tab", (bool*)&hook::g_bypass_alt_tab);
                CustomMenu::g_menu.Toggle("Bypass AFK Detection", &g_bypassAFK);
                CustomMenu::g_menu.Toggle("No Loss on Leave", &g_noLoss);
                if (g_noLoss)
                    CustomMenu::g_menu.Label("Enable before leaving match", CustomMenu::Colors::Warning);
                CustomMenu::g_menu.EndSection();
            }
        }

        // ===================== TAB 1: FUT =====================
        else if (tab == 1)
        {
            if (s_tabSwitchFrame) log::to_file("[TAB1] BeginSection\r\n");
            if (CustomMenu::g_menu.BeginSection("Division Rivals"))
            {
                if (s_tabSwitchFrame) log::to_file("[TAB1] StatusIndicator\r\n");
                CustomMenu::g_menu.StatusIndicator("System", division::IsReady());

                // Division combo (always visible so user can pick a division)
                static const char* divLabels[] = {
                    "None", "DIV 10", "DIV 9", "DIV 8", "DIV 7", "DIV 6",
                    "DIV 5", "DIV 4", "DIV 3", "DIV 2", "DIV 1",
                    "ELITE 500", "ELITE 3000"
                };

                if (s_tabSwitchFrame) log::to_file("[TAB1] Combo\r\n");
                int prevDiv = division::selectedDivision;
                CustomMenu::g_menu.Combo("Division", &division::selectedDivision, divLabels, 13);
                if (division::selectedDivision != prevDiv)
                    division::UpdateValues(division::selectedDivision);

                if (s_tabSwitchFrame) log::to_file("[TAB1] IsReady check\r\n");
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
                            CustomMenu::g_menu.Label("Easy matchmaking active", CustomMenu::Colors::Success);
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

        // ===================== TAB 2: Sliders =====================
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
                        RebindCommonHotkey(hk_applySliders, nk, hk_do_applySliders);
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
                        RebindCommonHotkey(hk_swapSettings, nk, hk_do_swapSettings);
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
                CustomMenu::g_menu.SliderFloat("Acceleration##L",        &sliders::local_acceleration, 1.0f, 99.0f);
                CustomMenu::g_menu.SliderFloat("Sprint Speed##L",        &sliders::local_sprint, 1.0f, 99.0f);
                CustomMenu::g_menu.SliderFloat("Shoot Error##L",         &sliders::local_shoot_error, 1.0f, 99.0f);
                CustomMenu::g_menu.SliderFloat("Shoot Speed##L",         &sliders::local_shoot_speed, 1.0f, 99.0f);
                CustomMenu::g_menu.SliderFloat("Pass Error##L",          &sliders::local_pass_error, 1.0f, 99.0f);
                CustomMenu::g_menu.SliderFloat("Pass Speed##L",          &sliders::local_pass_speed, 1.0f, 99.0f);
                CustomMenu::g_menu.SliderFloat("First Touch Error##L",   &sliders::local_first_touch_error, 1.0f, 99.0f);
                CustomMenu::g_menu.SliderFloat("Header Shot Error##L",   &sliders::local_header_shot_error, 1.0f, 99.0f);
                CustomMenu::g_menu.SliderFloat("Header Pass Error##L",   &sliders::local_header_pass_error, 1.0f, 99.0f);
                CustomMenu::g_menu.SliderFloat("Intercept Error##L",     &sliders::local_intercept_error, 1.0f, 99.0f);
                CustomMenu::g_menu.SliderFloat("Ball Deflection##L",     &sliders::local_ball_deflection, 1.0f, 99.0f);
                CustomMenu::g_menu.SliderFloat("Marking##L",             &sliders::local_position_marking, 1.0f, 99.0f);
                CustomMenu::g_menu.SliderFloat("Line Length##L",         &sliders::local_position_line_length, 1.0f, 99.0f);
                CustomMenu::g_menu.SliderFloat("Line Width##L",          &sliders::local_position_line_width, 1.0f, 99.0f);
                CustomMenu::g_menu.SliderFloat("Def. Line Height##L",    &sliders::local_position_defensive_line_height, 1.0f, 99.0f);
                CustomMenu::g_menu.SliderFloat("Run Frequency##L",       &sliders::local_position_run_frequency, 1.0f, 99.0f);
                CustomMenu::g_menu.SliderFloat("Fullback Pos##L",        &sliders::local_position_fullback, 1.0f, 99.0f);
                CustomMenu::g_menu.SliderFloat("GK Ability##L",          &sliders::local_gk_ability, 1.0f, 99.0f);
                CustomMenu::g_menu.SliderFloat("Tackle Aggression##L",   &sliders::local_tackle_aggression, 1.0f, 99.0f);
                CustomMenu::g_menu.SliderFloat("Injury Severity##L",     &sliders::local_injury_severity, 1.0f, 99.0f);
                CustomMenu::g_menu.SliderFloat("Injury Frequency##L",    &sliders::local_injury_frequency, 1.0f, 99.0f);
                CustomMenu::g_menu.EndSection();
            }

            // ── Section 4: Opponent Sliders ──
            if (CustomMenu::g_menu.BeginSection("Opponent Sliders"))
            {
                CustomMenu::g_menu.SliderFloat("Acceleration##O",        &sliders::opp_acceleration, 1.0f, 99.0f);
                CustomMenu::g_menu.SliderFloat("Sprint Speed##O",        &sliders::opp_sprint, 1.0f, 99.0f);
                CustomMenu::g_menu.SliderFloat("Shoot Error##O",         &sliders::opp_shoot_error, 1.0f, 99.0f);
                CustomMenu::g_menu.SliderFloat("Shoot Speed##O",         &sliders::opp_shoot_speed, 1.0f, 99.0f);
                CustomMenu::g_menu.SliderFloat("Pass Error##O",          &sliders::opp_pass_error, 1.0f, 99.0f);
                CustomMenu::g_menu.SliderFloat("Pass Speed##O",          &sliders::opp_pass_speed, 1.0f, 99.0f);
                CustomMenu::g_menu.SliderFloat("First Touch Error##O",   &sliders::opp_first_touch_error, 1.0f, 99.0f);
                CustomMenu::g_menu.SliderFloat("Header Shot Error##O",   &sliders::opp_header_shot_error, 1.0f, 99.0f);
                CustomMenu::g_menu.SliderFloat("Header Pass Error##O",   &sliders::opp_header_pass_error, 1.0f, 99.0f);
                CustomMenu::g_menu.SliderFloat("Intercept Error##O",     &sliders::opp_intercept_error, 1.0f, 99.0f);
                CustomMenu::g_menu.SliderFloat("Ball Deflection##O",     &sliders::opp_ball_deflection, 1.0f, 99.0f);
                CustomMenu::g_menu.SliderFloat("Marking##O",             &sliders::opp_position_marking, 1.0f, 99.0f);
                CustomMenu::g_menu.SliderFloat("Line Length##O",         &sliders::opp_position_line_length, 1.0f, 99.0f);
                CustomMenu::g_menu.SliderFloat("Line Width##O",          &sliders::opp_position_line_width, 1.0f, 99.0f);
                CustomMenu::g_menu.SliderFloat("Def. Line Height##O",    &sliders::opp_position_defensive_line_height, 1.0f, 99.0f);
                CustomMenu::g_menu.SliderFloat("Run Frequency##O",       &sliders::opp_position_run_frequency, 1.0f, 99.0f);
                CustomMenu::g_menu.SliderFloat("Fullback Pos##O",        &sliders::opp_position_fullback, 1.0f, 99.0f);
                CustomMenu::g_menu.SliderFloat("GK Ability##O",          &sliders::opp_gk_ability, 1.0f, 99.0f);
                CustomMenu::g_menu.SliderFloat("Tackle Aggression##O",   &sliders::opp_tackle_aggression, 1.0f, 99.0f);
                CustomMenu::g_menu.SliderFloat("Injury Severity##O",     &sliders::opp_injury_severity, 1.0f, 99.0f);
                CustomMenu::g_menu.SliderFloat("Injury Frequency##O",    &sliders::opp_injury_frequency, 1.0f, 99.0f);
                CustomMenu::g_menu.EndSection();
            }
        }

        // ===================== TAB 3: Rage (Premium only) =====================
#ifndef STANDARD_BUILD
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
                static const char* reasons[] = {
                    "Opponent Quit", "End Match Early", "Squad Mismatch",
                    "Both Get Loss", "Forfeit", "Local Idle H2H",
                    "Own Goals", "Own Goals H2H", "Constrained",
                    "Squad Error", "ID 19", "ID 20", "ID 21", "ID 22"
                };
                CustomMenu::g_menu.Combo("Reason", &g_dcReason, reasons, 14);

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
            if (CustomMenu::g_menu.BeginSection("AI Control"))
            {
                CustomMenu::g_menu.Toggle("AI vs Opponents", &g_aiVsOpps);
                CustomMenu::g_menu.Label("Your team plays on autopilot", CustomMenu::Colors::TextSecondary);
                CustomMenu::g_menu.EndSection();
            }

            if (CustomMenu::g_menu.BeginSection("Opponent AI"))
            {
                CustomMenu::g_menu.Toggle("Disable Opponent AI", &g_disableAi);
                CustomMenu::g_menu.Label("Opponent players stop moving", CustomMenu::Colors::TextSecondary);
                CustomMenu::g_menu.Label("Re-sends every 3s (resets after goals)", CustomMenu::Colors::Warning);
                CustomMenu::g_menu.EndSection();
            }

            if (CustomMenu::g_menu.BeginSection("AI Difficulty"))
            {
                static bool aiLocalLegendary = false;
                static bool aiOpponentBeginner = false;
                CustomMenu::g_menu.Toggle("AI Local Legendary", &aiLocalLegendary);
                CustomMenu::g_menu.Toggle("AI Opponent Beginner", &aiOpponentBeginner);
                CustomMenu::g_menu.Label("Requires hooks -- not yet active", CustomMenu::Colors::Warning);
                CustomMenu::g_menu.EndSection();
            }
        }

        // ===================== TAB 5: Squad Battles =====================
        else if (tab == 5)
        {
            if (CustomMenu::g_menu.BeginSection("Difficulty"))
            {
                static int selectedDifficulty = 0;
                static const char* difficulties[] = {
                    "Beginner", "Amateur", "Semi-Pro", "Professional", "World Class", "Legendary", "Ultimate"
                };
                CustomMenu::g_menu.Combo("AI Difficulty", &selectedDifficulty, difficulties, 7);
                if (CustomMenu::g_menu.ButtonColored("Apply Difficulty", CustomMenu::Colors::Success, -1, 28))
                    toast::Show(toast::Type::Info, "Difficulty set (needs offset)");
                CustomMenu::g_menu.EndSection();
            }

            if (CustomMenu::g_menu.BeginSection("Match Timer"))
            {
                static bool freezeTimer = false;
                static float timerSpeed = 1.0f;
                CustomMenu::g_menu.Toggle("Freeze Match Timer", &freezeTimer);
                static bool resetTimer = false;
                CustomMenu::g_menu.Toggle("Reset Match Timer", &resetTimer);
                static bool setCustomTime = false;
                static int customMinutes = 0;
                CustomMenu::g_menu.Toggle("Set Custom Time", &setCustomTime);
                if (setCustomTime)
                    CustomMenu::g_menu.SliderInt("Minutes", &customMinutes, 0, 44);
                CustomMenu::g_menu.SliderFloat("Timer Speed", &timerSpeed, 0.1f, 40.0f);
                CustomMenu::g_menu.Label("Timer features need offset verification", CustomMenu::Colors::Warning);
                CustomMenu::g_menu.EndSection();
            }

            if (CustomMenu::g_menu.BeginSection("Ball Control"))
            {
                CustomMenu::g_menu.Label("HIGH RISK - use sliders instead", CustomMenu::Colors::Warning);
                static bool freezeBall = false;
                static bool leftGoal = false;
                static bool rightGoal = false;
                CustomMenu::g_menu.Toggle("Freeze Ball", &freezeBall);
                CustomMenu::g_menu.Toggle("Left Goal", &leftGoal);
                CustomMenu::g_menu.Toggle("Right Goal", &rightGoal);
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
                CustomMenu::g_menu.Label("Pro Club hooks not yet active", CustomMenu::Colors::Warning);
                CustomMenu::g_menu.EndSection();
            }

            if (CustomMenu::g_menu.BeginSection("AI Playstyles"))
            {
                CustomMenu::g_menu.Label("Must be captain", CustomMenu::Colors::Warning);
                static int aiPlaystyle = 0;
                static const char* playstyles[] = { "None", "Plus", "Silver" };
                CustomMenu::g_menu.Combo("AI Playstyle", &aiPlaystyle, playstyles, 3);
                CustomMenu::g_menu.EndSection();
            }

            if (CustomMenu::g_menu.BeginSection("Player Playstyles"))
            {
                CustomMenu::g_menu.Label("Must be captain", CustomMenu::Colors::Warning);
                static int playerPlaystyle = 0;
                static const char* playstyles2[] = { "None", "Plus", "Silver" };
                CustomMenu::g_menu.Combo("Your Playstyle", &playerPlaystyle, playstyles2, 3);
                CustomMenu::g_menu.EndSection();
            }
        }

        // ===================== TAB 7: Misc =====================
        else if (tab == 7)
        {
            // ── Foul Control (WIP — disabled for now) ──
            // if (CustomMenu::g_menu.BeginSection("Foul Control"))
            // {
            //     CustomMenu::g_menu.Toggle("No Fouls", &g_noFouls);
            //     CustomMenu::g_menu.Toggle("No Offside", &g_noOffside);
            //     CustomMenu::g_menu.Toggle("No Handball", &g_noHandball);
            //     CustomMenu::g_menu.Toggle("No Booking", &g_noBooking);
            //     CustomMenu::g_menu.Label("Local/offline matches only", CustomMenu::Colors::Warning);
            //     CustomMenu::g_menu.EndSection();
            // }

            if (CustomMenu::g_menu.BeginSection("Camera Settings"))
            {
                static bool enableHeightCam = false;
                static int heightScale = 0;
                static bool enableZoomCam = false;
                static int zoomScale = 0;

                static const char* heightOptions[] = { "x200", "x500", "x1000", "x2000", "x5000" };
                static const char* zoomOptions[] = { "x2", "x5", "x10", "x20" };

                CustomMenu::g_menu.Toggle("Height Camera", &enableHeightCam);
                if (enableHeightCam)
                    CustomMenu::g_menu.Combo("Height Scale", &heightScale, heightOptions, 5);

                CustomMenu::g_menu.Toggle("Zoom Camera", &enableZoomCam);
                if (enableZoomCam)
                    CustomMenu::g_menu.Combo("Zoom Scale", &zoomScale, zoomOptions, 4);

                CustomMenu::g_menu.Label("Camera needs settings hook", CustomMenu::Colors::Warning);
                CustomMenu::g_menu.EndSection();
            }

            if (CustomMenu::g_menu.BeginSection("Hotkeys"))
            {
                CustomMenu::g_menu.LabelValue("Toggle Menu", "INSERT / F5");

#ifndef STANDARD_BUILD
                // ── Rage hotkey bindings ──
                if (hk_bind_crash) {
                    CustomMenu::g_menu.Label("Press a key for Crash...", CustomMenu::Colors::Warning);
                    int newKey = hk_crash;
                    if (menu::BindHotkeyPoll(newKey, hk_bind_crash))
                        RebindRageHotkey(hk_crash, newKey, hk_do_crash);
                } else {
                    CustomMenu::g_menu.LabelValue("Crash Opponent", menu::GetKeyName(hk_crash));
                    if (CustomMenu::g_menu.Button("Rebind##crash", 80, 24))
                    {
                        hk_bind_crash = true;
                        menu::gIsBindingAnyHotkey = true;
                    }
                }

                if (hk_bind_freeze1) {
                    CustomMenu::g_menu.Label("Press a key for Freeze 1...", CustomMenu::Colors::Warning);
                    int newKey = hk_freeze1;
                    if (menu::BindHotkeyPoll(newKey, hk_bind_freeze1))
                        RebindRageHotkey(hk_freeze1, newKey, hk_do_freeze1);
                } else {
                    CustomMenu::g_menu.LabelValue("Freeze 1 (PC/XBOX)", menu::GetKeyName(hk_freeze1));
                    if (CustomMenu::g_menu.Button("Rebind##freeze1", 80, 24))
                    {
                        hk_bind_freeze1 = true;
                        menu::gIsBindingAnyHotkey = true;
                    }
                }

                if (hk_bind_freeze2) {
                    CustomMenu::g_menu.Label("Press a key for Freeze 2...", CustomMenu::Colors::Warning);
                    int newKey = hk_freeze2;
                    if (menu::BindHotkeyPoll(newKey, hk_bind_freeze2))
                        RebindRageHotkey(hk_freeze2, newKey, hk_do_freeze2);
                } else {
                    CustomMenu::g_menu.LabelValue("Freeze 2", menu::GetKeyName(hk_freeze2));
                    if (CustomMenu::g_menu.Button("Rebind##freeze2", 80, 24))
                    {
                        hk_bind_freeze2 = true;
                        menu::gIsBindingAnyHotkey = true;
                    }
                }

                if (hk_bind_slider) {
                    CustomMenu::g_menu.Label("Press a key for Slider Bomb...", CustomMenu::Colors::Warning);
                    int newKey = hk_slider;
                    if (menu::BindHotkeyPoll(newKey, hk_bind_slider))
                        RebindRageHotkey(hk_slider, newKey, hk_do_slider);
                } else {
                    CustomMenu::g_menu.LabelValue("Slider Bomb", menu::GetKeyName(hk_slider));
                    if (CustomMenu::g_menu.Button("Rebind##slider", 80, 24))
                    {
                        hk_bind_slider = true;
                        menu::gIsBindingAnyHotkey = true;
                    }
                }

                if (hk_bind_kick) {
                    CustomMenu::g_menu.Label("Press a key for Kick...", CustomMenu::Colors::Warning);
                    int newKey = hk_kick;
                    if (menu::BindHotkeyPoll(newKey, hk_bind_kick))
                        RebindRageHotkey(hk_kick, newKey, hk_do_kick);
                } else {
                    CustomMenu::g_menu.LabelValue("Kick Opponent", menu::GetKeyName(hk_kick));
                    if (CustomMenu::g_menu.Button("Rebind##kick", 80, 24))
                    {
                        hk_bind_kick = true;
                        menu::gIsBindingAnyHotkey = true;
                    }
                }
#endif // !STANDARD_BUILD

                CustomMenu::g_menu.EndSection();
            }
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

        } __except(1) {
            char ebuf[64];
            fmt::snprintf(ebuf, sizeof(ebuf), "[OVL] CRASH in tab %d!\r\n", tab);
            log::to_file(ebuf);
        }

        if (s_tabSwitchFrame) log::to_file("[OVL] EndWindow\r\n");
        CustomMenu::g_menu.EndWindow();
    }

    if (s_tabSwitchFrame) log::to_file("[OVL] EndFrame\r\n");
    CustomMenu::g_menu.EndFrame();
    if (s_tabSwitchFrame) log::to_file("[OVL] EndFrame done\r\n");

    // ── Per-frame features (run even when menu is closed) ──
    if (g_rageReady && rage::slider_ptr)
    {
        __try {
            uintptr_t base = *(uintptr_t*)rage::slider_ptr;
            if (base)
            {
                // Anti-AFK: reset timer to huge value
                if (g_bypassAFK)
                {
                    uintptr_t p1 = *(uintptr_t*)(base + 0x1090);
                    if (p1) {
                        uintptr_t p2 = *(uintptr_t*)(p1 + 0x130);
                        if (p2) {
                            float* timer = (float*)(p2 + 0x4CA4);
                            if (*timer != 1000000.0f)
                                *timer = 1000000.0f;
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
                uintptr_t function_rcx = *(uintptr_t*)rage::msg_dispatcher;
                if (function_rcx && rage::dispatch_vfunc) {
                    uint64_t opcode = 0xA2CB726E;
                    int ourSide = sliders::playerside;

                    for (int i = 2; i < 12; i++) {
                        unsigned int buffer[3] = { (unsigned int)ourSide, (unsigned int)i, 0 };

                        hook::g_allow_attack_send = true;
                        typedef void(__fastcall* dispatch_fn_t)(
                            uint64_t, uint64_t*, uint64_t*, void*, int, char, unsigned char);
                        auto fn = reinterpret_cast<dispatch_fn_t>(rage::dispatch_vfunc);
                        spoof_call(fn, (uint64_t)function_rcx,
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
                uintptr_t function_rcx = *(uintptr_t*)rage::msg_dispatcher;
                if (function_rcx && rage::dispatch_vfunc) {
                    uint64_t opcode = 0xA2CB726E;
                    int oppSide = (sliders::playerside == 0) ? 1 : 0;

                    for (int i = 2; i < 12; i++) {
                        unsigned int buffer[3] = { (unsigned int)oppSide, (unsigned int)i, 0 };

                        hook::g_allow_attack_send = true;
                        typedef void(__fastcall* dispatch_fn_t)(
                            uint64_t, uint64_t*, uint64_t*, void*, int, char, unsigned char);
                        auto fn = reinterpret_cast<dispatch_fn_t>(rage::dispatch_vfunc);
                        spoof_call(fn, (uint64_t)function_rcx,
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

    if (s_first) { log::to_file("[OVL] Done\r\n"); s_first = false; }
}
