# Encrypted Strings — Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Land a working `src/crt/skcrypt.h` and convert the purely init-time modules (`game`, `main`, `comms`, `input`, `offsets`) so that their plaintext string literals disappear from `FC26Standard.dll` / `FC26Premium.dll`.

**Architecture:** Custom C++20 `consteval`-based header. String literals are XOR-encrypted at compile time into a trivially-copyable stack holder. Call sites use `skCrypt("...")` / `skCryptW(L"...")` macros. Explicit `.decrypt()` does in-place XOR and returns `const CharT*`; `.clear()` wipes the stack buffer via `volatile` writes. Scalar byte XOR only — no SIMD, no CRT symbols, no privileged instructions. Safe for this project's NOCRT / hypervisor-adjacent environment.

**Tech Stack:** MSVC v143, C++20 (`/std:c++20`), Windows x64 DLL, `NOCRT_BUILD`, no exceptions, no RTTI, `BufferSecurityCheck=false`, `/Zc:threadSafeInit-`.

**Spec:** `docs/superpowers/specs/2026-04-24-encrypted-strings-design.md`

**Build environment note:** This project builds on Windows via MSBuild/Visual Studio. Some verification steps below require `strings.exe` (Sysinternals) and the ability to inject the built DLL into FC26 — those must be run on a Windows box.

---

### Task 1: Create the encrypted-string header

**Files:**
- Create: `src/crt/skcrypt.h`

- [ ] **Step 1: Write `src/crt/skcrypt.h` with the full implementation**

Write this complete file:

```cpp
#pragma once

// Compile-time string encryption — SkCrypt-style API.
//
// Usage:
//   auto s = skCrypt("some text");       // char
//   auto w = skCryptW(L"fc26.exe");      // wchar_t
//   const char*    p = s.decrypt();      // returns stack buffer, valid for s's lifetime
//   const wchar_t* q = w.decrypt();
//   s.clear();                            // wipe when done
//   w.clear();
//
// Semantics:
//   * Literal is encrypted at compile time. Plaintext never lands in .rdata.
//   * decrypt() XORs buf[] in-place. Calling it a second time re-encrypts
//     (XOR is its own inverse). Canonical usage is decrypt() -> use -> clear().
//   * clear() writes zeros via volatile so MSVC cannot elide the wipe.
//   * No destructor: holder is a POD. If you forget clear(), the stack buffer
//     keeps plaintext until the frame is overwritten by subsequent calls.
//
// Temporary-lifetime gotcha:
//   Safe:   log::debug(skCrypt("x").decrypt());   // temp lives until ';'
//   UNSAFE: const char* p = skCrypt("x").decrypt(); log::debug(p); // UB: holder gone
//   Always bind to a named local if you want to call clear().
//
// NOCRT / hypervisor-safety:
//   No CRT calls. Pure scalar byte XOR. #pragma loop(no_vector) prevents
//   MSVC from auto-vectorizing to SSE2/AVX. Nothing here VM-exits or
//   interacts with hvax64.
//
// Kill-switch:
//   Define SKCRYPT_DISABLE before including this header (or globally) to
//   replace encryption with a passthrough wrapper. Lets us bisect regressions
//   without ripping out call sites.

namespace sk
{
    // 32-bit per-call-site key derived from __COUNTER__, __LINE__, and a
    // fixed build salt. Must be constexpr so it evaluates at compile time.
    constexpr unsigned make_key(unsigned counter, unsigned line)
    {
        unsigned v = (counter * 2654435761u) ^ (line * 1315423911u) ^ 0xC0FFEE42u;
        return v ? v : 1u;
    }
}

#ifdef SKCRYPT_DISABLE

namespace sk
{
    template <typename CharT, unsigned N>
    struct passthrough
    {
        const CharT* p;
        __forceinline const CharT* decrypt() const { return p; }
        __forceinline void clear() const {}
    };

    template <typename CharT, unsigned N>
    constexpr passthrough<CharT, N> wrap(const CharT (&src)[N]) { return { src }; }
}

#define skCrypt(s)  (::sk::wrap<char,    sizeof(s)>(s))
#define skCryptW(s) (::sk::wrap<wchar_t, sizeof(s) / sizeof(wchar_t)>(s))

#else

namespace sk
{
    // Trivially-copyable POD. Lives on the stack at the call site.
    // N includes the terminating null character/wchar.
    template <typename CharT, unsigned N>
    struct holder
    {
        CharT buf[N];
        unsigned char key[4];

        __forceinline const CharT* decrypt()
        {
#pragma loop(no_vector)
            for (unsigned i = 0; i < N; ++i)
            {
                buf[i] = (CharT)((unsigned)buf[i] ^ (unsigned)key[i & 3u]);
            }
            return buf;
        }

        __forceinline void clear()
        {
            volatile CharT* vb = buf;
#pragma loop(no_vector)
            for (unsigned i = 0; i < N; ++i)
            {
                vb[i] = (CharT)0;
            }
        }
    };

    // consteval factory — forces compile-time encryption. The source literal
    // never makes it into the binary; only the encrypted `holder` does.
    template <typename CharT, unsigned N>
    consteval holder<CharT, N> build(const CharT (&src)[N], unsigned k)
    {
        holder<CharT, N> h{};
        h.key[0] = (unsigned char)(k & 0xFFu);
        h.key[1] = (unsigned char)((k >> 8) & 0xFFu);
        h.key[2] = (unsigned char)((k >> 16) & 0xFFu);
        h.key[3] = (unsigned char)((k >> 24) & 0xFFu);
        for (unsigned i = 0; i < N; ++i)
        {
            h.buf[i] = (CharT)((unsigned)src[i] ^ (unsigned)h.key[i & 3u]);
        }
        return h;
    }
}

#define skCrypt(s)  (::sk::build<char,    sizeof(s)>                     (s, ::sk::make_key(__COUNTER__, __LINE__)))
#define skCryptW(s) (::sk::build<wchar_t, sizeof(s) / sizeof(wchar_t)>   (s, ::sk::make_key(__COUNTER__, __LINE__)))

#endif // SKCRYPT_DISABLE
```

- [ ] **Step 2: Add the new header to the vcxproj `<ItemGroup>` of headers**

**Files:**
- Modify: `FC26-ZeroHook.vcxproj` — add `<ClInclude Include="src\crt\skcrypt.h" />` to the header `<ItemGroup>` (the one containing other `src\crt\*.h` entries; currently `crt.h` is implicitly included but `skcrypt.h` must be added if the existing pattern uses explicit entries — search for `src\crt\crt.h` in the .vcxproj; if present, mirror it, if absent, skip this step).

Confirm by searching:
```
grep -n 'crt\\crt.h' FC26-ZeroHook.vcxproj
```
If it returns nothing, the .vcxproj does not enumerate crt headers explicitly, so no .vcxproj edit is needed.

- [ ] **Step 3: Commit the header in isolation**

```bash
git add src/crt/skcrypt.h FC26-ZeroHook.vcxproj
git commit -m "crt: add skcrypt.h — compile-time string encryption header

Custom C++20 consteval header. skCrypt('...') / skCryptW(L'...')
encrypt at compile time into a stack holder; decrypt() does in-place
XOR, clear() wipes via volatile. NOCRT-compliant (no CRT symbols,
scalar XOR only, #pragma loop(no_vector)). Hypervisor-safe (no SIMD,
no privileged instructions). SKCRYPT_DISABLE macro available for
kill-switch."
```

---

### Task 2: Canary test — prove plaintext is stripped and runtime works

Before converting any real call site, validate the header mechanics with a canary string.

**Files:**
- Modify: `src/main.cpp` (temporary — removed in Step 5)

- [ ] **Step 1: Add a temporary canary at the top of `DllMain`**

Open `src/main.cpp`. At the very top of the `if (fdwReason == DLL_PROCESS_ATTACH)` block (immediately after the `{`, before the existing `log::to_file(...)` call on line 18), insert:

```cpp
#include "crt/skcrypt.h"   // at top of file with other includes
// ...
        // TEMPORARY CANARY — remove in Task 2 Step 5
        {
            auto canary = skCrypt("SKCRYPT_CANARY_ZQXJWV_PLAINTEXT_MARKER_42");
            log::to_file(canary.decrypt());
            canary.clear();
        }
```

Full include line (add at the top with the other includes, line 2 area):

```cpp
#include "crt/skcrypt.h"
```

- [ ] **Step 2: Build the Standard configuration on Windows**

Run on Windows (from VS Developer Command Prompt, at the repo root):

```
msbuild FC26-ZeroHook.sln /p:Configuration=Standard /p:Platform=x64
```

Expected: `Build succeeded. 0 Warning(s) 0 Error(s)`.

If you get `C2672` / `C2975` (consteval-related template errors) — confirm `/std:c++20` is in effect (it is, per the .vcxproj) and that the header was saved exactly as written.

- [ ] **Step 3: Verify the canary plaintext is absent from the built DLL**

Run (on Windows, from the build output directory):

```
strings.exe FC26Standard.dll | findstr SKCRYPT_CANARY_ZQXJWV
```

Expected: **no output** (exit code 1). If the marker appears, encryption is not working — inspect the holder emission in IDA to see whether MSVC kept the literal around; stop and debug before proceeding.

Also run:

```
strings.exe FC26Standard.dll | findstr PLAINTEXT_MARKER_42
```

Expected: **no output**.

- [ ] **Step 4: Verify runtime decryption round-trips correctly**

Inject the DLL into FC26 (use your existing injection tooling), let it run to `DLL_PROCESS_ATTACH`, detach.

Open `%USERPROFILE%\Documents\zerohook.log`. Search for `SKCRYPT_CANARY_ZQXJWV_PLAINTEXT_MARKER_42`.

Expected: **exactly one line** containing the full plaintext. This proves compile-time encrypt + runtime decrypt is lossless.

- [ ] **Step 5: Remove the canary code**

Delete the temporary canary block from `src/main.cpp` (the 5 lines added in Step 1). Keep the `#include "crt/skcrypt.h"` at the top — it stays for Task 4.

- [ ] **Step 6: Do NOT commit yet** — the canary's sole purpose was validation; Task 4 commits the real `main.cpp` changes in one coherent commit.

---

### Task 3: Verify the `SKCRYPT_DISABLE` kill-switch works

**Files:**
- Modify: `src/crt/skcrypt.h` (temporary define) or global preprocessor (preferred)

- [ ] **Step 1: Temporarily enable the kill-switch via preprocessor**

Edit `FC26-ZeroHook.vcxproj` — find the `<PreprocessorDefinitions>` entry for the Standard config (it currently reads `NDEBUG;_WINDOWS;_USRDLL;NOCRT_BUILD;STANDARD_BUILD;%(PreprocessorDefinitions)`) and add `SKCRYPT_DISABLE;`:

```
NDEBUG;_WINDOWS;_USRDLL;NOCRT_BUILD;STANDARD_BUILD;SKCRYPT_DISABLE;%(PreprocessorDefinitions)
```

- [ ] **Step 2: Add a canary again (same as Task 2 Step 1) to `src/main.cpp`**

This is a disposable canary for this task only; use a different marker to avoid confusion:

```cpp
        // TEMPORARY KILL-SWITCH CANARY — remove at end of Task 3
        {
            auto canary = skCrypt("SKCRYPT_KILLSWITCH_CANARY_MPLX_MARKER");
            log::to_file(canary.decrypt());
            canary.clear();
        }
```

- [ ] **Step 3: Rebuild Standard**

Run: `msbuild FC26-ZeroHook.sln /p:Configuration=Standard /p:Platform=x64`
Expected: clean build.

- [ ] **Step 4: Verify the kill-switch makes plaintext visible**

Run: `strings.exe FC26Standard.dll | findstr SKCRYPT_KILLSWITCH_CANARY_MPLX_MARKER`
Expected: **one hit**. When `SKCRYPT_DISABLE` is defined, call sites pass the literal through unchanged — so it DOES show up in `.rdata`. That proves the kill-switch path compiles and is effective.

- [ ] **Step 5: Revert the kill-switch**

- Remove `SKCRYPT_DISABLE;` from the vcxproj `<PreprocessorDefinitions>` for Standard.
- Remove the temporary canary block from `src/main.cpp`.

- [ ] **Step 6: Rebuild and confirm plaintext is gone again**

Run: `msbuild FC26-ZeroHook.sln /p:Configuration=Standard /p:Platform=x64`
Run: `strings.exe FC26Standard.dll | findstr SKCRYPT_KILLSWITCH_CANARY_MPLX_MARKER`
Expected: no output (canary is gone from source) — and also confirms we've fully reverted.

- [ ] **Step 7: Do NOT commit** — no real changes survive Task 3. The kill-switch verification is a one-time smoke test.

---

### Task 4: Convert `src/game/game.cpp` — the `fc26.exe` target array

The smallest, simplest conversion: a fixed-size array of three wide-string literals.

**Files:**
- Modify: `src/game/game.cpp` (lines ~107–141)

- [ ] **Step 1: Add the skcrypt include if missing**

At the top of `src/game/game.cpp`, verify `#include "../crt/skcrypt.h"` is present. If not, add it alongside the other `../` relative includes. (Check first:
```
grep -n 'skcrypt.h' src/game/game.cpp
```
If empty, add the include.)

- [ ] **Step 2: Replace the target array and match loop**

Replace lines 107–141 of `src/game/game.cpp` (the `const wchar_t* targets[] = { ... }` declaration and the subsequent match loop) with:

```cpp
    auto t0 = skCryptW(L"fc26.exe");
    auto t1 = skCryptW(L"fc26_trial.exe");
    auto t2 = skCryptW(L"fc26_showcase.exe");
    const wchar_t* targets[] = { t0.decrypt(), t1.decrypt(), t2.decrypt() };

    while (entry != list)
    {
        R1_LDR_DATA_TABLE_ENTRY* mod = CONTAINING_RECORD(entry, R1_LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        if (mod->FullDllName.Buffer)
        {
            wchar_t* fullPath = mod->FullDllName.Buffer;
            wchar_t* fileName = fullPath;
            for (wchar_t* p = fullPath; *p; p++)
            {
                if (*p == L'\\' || *p == L'/') fileName = p + 1;
            }

            for (int i = 0; i < 3; i++)
            {
                const wchar_t* t = targets[i];
                const wchar_t* f = fileName;
                bool match = true;
                while (*t)
                {
                    wchar_t fc = (*f >= L'A' && *f <= L'Z') ? (*f + 32) : *f;
                    if (fc != *t) { match = false; break; }
                    t++; f++;
                }
                if (match && *f == L'\0')
                {
                    t0.clear(); t1.clear(); t2.clear();
                    return { mod->DllBase, mod->SizeOfImage };
                }
            }
        }
        entry = entry->Flink;
    }

    t0.clear(); t1.clear(); t2.clear();
```

Note: `targets[i]` now points into the stack buffers of `t0`/`t1`/`t2`, which live in the same function frame — pointer validity is fine. `.clear()` is called on both return paths (match-found and loop-exit).

- [ ] **Step 3: Build Standard**

Run: `msbuild FC26-ZeroHook.sln /p:Configuration=Standard /p:Platform=x64`
Expected: clean build.

- [ ] **Step 4: Static verification**

Run: `strings.exe FC26Standard.dll | findstr /I "fc26.exe fc26_trial fc26_showcase"`
Expected: **no hits**. The plaintext `fc26.exe`, `fc26_trial.exe`, `fc26_showcase.exe` must be completely absent from the binary.

- [ ] **Step 5: Runtime smoke**

Inject into FC26. Expected: DLL loads, `offsets::Init()` succeeds (it depends on `game::find_module()` finding `fc26.exe`). If offsets fail, something is wrong with the decrypt. Check `zerohook.log` for the `[offsets] [1/7]` messages — success messages prove the module was matched via the decrypted target array.

- [ ] **Step 6: Commit**

```bash
git add src/game/game.cpp
git commit -m "game: encrypt fc26.exe target array via skCryptW

Three wide literals that previously appeared verbatim in the DLL's
.rdata (and IDA Strings view) are now compile-time encrypted. They
are decrypted into stack buffers for the match loop and cleared on
every exit path."
```

---

### Task 5: Convert `src/main.cpp` — DllMain bootstrap strings

**Files:**
- Modify: `src/main.cpp`

- [ ] **Step 1: Verify the include is present**

`#include "crt/skcrypt.h"` was added in Task 2 Step 1 and retained. Confirm with:
```
grep -n 'skcrypt.h' src/main.cpp
```

- [ ] **Step 2: Convert every string literal in DllMain and `bridge::init`**

Replace the body of `if (fdwReason == DLL_PROCESS_ATTACH)` (lines 16–44) with:

```cpp
    if (fdwReason == DLL_PROCESS_ATTACH)
    {
        { auto s = skCrypt("[ZeroHook] FC26-ZeroHook injected\r\n"); log::to_file(s.decrypt()); s.clear(); }
        breadcrumb::rescue_previous();  // salvage last-stage from prior session (if any)
        { auto s = skCrypt("boot:dll_attach"); breadcrumb::set(s.decrypt()); s.clear(); }

        if (!offsets::Init())
        {
            auto s = skCrypt("[ZeroHook] ABORT: offsets::Init() failed\r\n");
            log::debug(s.decrypt());
            s.clear();
            return TRUE;
        }

        if (!comms::test_channel())
        {
            auto s = skCrypt("[ZeroHook] ABORT: NtClose channel not working\r\n");
            log::debug(s.decrypt());
            s.clear();
            return TRUE;
        }

        hook::install_dxgi_hooks();           { auto s = skCrypt("boot:dxgi_hooked");         breadcrumb::set(s.decrypt()); s.clear(); }
        hook::install_network_hooks();        { auto s = skCrypt("boot:network_hooked");      breadcrumb::set(s.decrypt()); s.clear(); }
        hook::install_playerside_hook();      { auto s = skCrypt("boot:playerside_hooked");   breadcrumb::set(s.decrypt()); s.clear(); }
        hook::install_match_timer_hook();     { auto s = skCrypt("boot:matchtimer_hooked");   breadcrumb::set(s.decrypt()); s.clear(); }
        hook::install_eaid_hook();            { auto s = skCrypt("boot:eaid_hooked");         breadcrumb::set(s.decrypt()); s.clear(); }
        ai_control::InstallStateMachineHook();{ auto s = skCrypt("boot:statemachine_hooked"); breadcrumb::set(s.decrypt()); s.clear(); }
                                              { auto s = skCrypt("boot:ai_trace_hooked");     breadcrumb::set(s.decrypt()); s.clear(); }

        { auto s = skCrypt("FC26"); bridge::init(s.decrypt()); s.clear(); }
        { auto s = skCrypt("boot:complete"); breadcrumb::set(s.decrypt()); s.clear(); }
    }

    return TRUE;
```

Reasoning: every `breadcrumb::set`, `log::to_file`, `log::debug`, and `bridge::init` call takes `const char*` and consumes the string synchronously, so `.decrypt()` → use → `.clear()` pattern is safe within each block scope.

- [ ] **Step 3: Build Standard**

Run: `msbuild FC26-ZeroHook.sln /p:Configuration=Standard /p:Platform=x64`
Expected: clean build.

- [ ] **Step 4: Static verification**

Run: `strings.exe FC26Standard.dll | findstr /C:"FC26-ZeroHook injected" /C:"offsets::Init() failed" /C:"NtClose channel not working" /C:"boot:dll_attach" /C:"boot:dxgi_hooked" /C:"boot:complete"`
Expected: **no hits** for any of these.

- [ ] **Step 5: Runtime smoke**

Inject into FC26. Expected in `zerohook.log`:
- Line containing `[ZeroHook] FC26-ZeroHook injected`
- Line(s) written by subsequent init (`[offsets] ...`, etc.)

Expected in `zerohook_crumb.log` (or check after a later boot via `rescue_previous`): crumb strings `boot:dll_attach`, `boot:dxgi_hooked`, ... `boot:complete`.

- [ ] **Step 6: Commit**

```bash
git add src/main.cpp
git commit -m "main: encrypt DllMain bootstrap strings via skCrypt

All 13 init-time literals (injection banner, abort messages, boot
breadcrumbs, bridge tag) are now compile-time encrypted. Plaintext
is no longer visible in the DLL's .rdata or IDA Strings view."
```

---

### Task 6: Convert `src/comms/comms.cpp`

Tiny file (22 lines, 3 literals).

**Files:**
- Modify: `src/comms/comms.cpp`

- [ ] **Step 1: Read current file**

```
cat src/comms/comms.cpp
```

- [ ] **Step 2: Add the include**

At the top of `src/comms/comms.cpp`, add (adjacent to other `../` includes):

```cpp
#include "../crt/skcrypt.h"
```

- [ ] **Step 3: Convert the three literals**

Replace the body so that:

- `log::debugf("[ZeroHook] Ping: status=%u, result=0x%llX\r\n", req.status, req.result);` becomes:
  ```cpp
  { auto s = skCrypt("[ZeroHook] Ping: status=%u, result=0x%llX\r\n"); log::debugf(s.decrypt(), req.status, req.result); s.clear(); }
  ```
- `log::debug("[ZeroHook] NtClose channel OK\r\n");` becomes:
  ```cpp
  { auto s = skCrypt("[ZeroHook] NtClose channel OK\r\n"); log::debug(s.decrypt()); s.clear(); }
  ```
- `log::debug("[ZeroHook] NtClose channel FAILED\r\n");` becomes:
  ```cpp
  { auto s = skCrypt("[ZeroHook] NtClose channel FAILED\r\n"); log::debug(s.decrypt()); s.clear(); }
  ```

- [ ] **Step 4: Build Standard**

Run: `msbuild FC26-ZeroHook.sln /p:Configuration=Standard /p:Platform=x64`
Expected: clean build.

- [ ] **Step 5: Static verification**

Run: `strings.exe FC26Standard.dll | findstr /C:"NtClose channel OK" /C:"NtClose channel FAILED" /C:"Ping: status"`
Expected: **no hits**.

- [ ] **Step 6: Runtime smoke**

Inject into FC26. Expected in `zerohook.log`: `[ZeroHook] NtClose channel OK` (or FAILED with context). If neither appears, decrypt didn't run — stop and inspect.

- [ ] **Step 7: Commit**

```bash
git add src/comms/comms.cpp
git commit -m "comms: encrypt NtClose channel init log strings

Three log lines emitted by comms::test_channel() at init are now
compile-time encrypted; 'NtClose channel OK' / 'FAILED' no longer
appear plaintext in the DLL."
```

---

### Task 7: Convert `src/input/frostbite_input.cpp`

Tiny file (44 lines, 3 literals in init).

**Files:**
- Modify: `src/input/frostbite_input.cpp`

- [ ] **Step 1: Add the include**

At the top of `src/input/frostbite_input.cpp`, add:

```cpp
#include "../crt/skcrypt.h"
```

- [ ] **Step 2: Convert the three literals**

- Line 19: `log::debug("[FBInput] InputReader vtable not resolved\r\n");` →
  ```cpp
  { auto s = skCrypt("[FBInput] InputReader vtable not resolved\r\n"); log::debug(s.decrypt()); s.clear(); }
  ```
- Lines 38–39: 
  ```cpp
  log::debugf("[FBInput] reader=%p  isMouseDown=%p\r\n",
      (void*)s_reader, (void*)s_fnIsMouseDown);
  ```
  → replace with:
  ```cpp
  {
      auto s = skCrypt("[FBInput] reader=%p  isMouseDown=%p\r\n");
      log::debugf(s.decrypt(), (void*)s_reader, (void*)s_fnIsMouseDown);
      s.clear();
  }
  ```
- Line 42: `log::debug("[FBInput] Init OK (EPT hooks handle input blocking)\r\n");` →
  ```cpp
  { auto s = skCrypt("[FBInput] Init OK (EPT hooks handle input blocking)\r\n"); log::debug(s.decrypt()); s.clear(); }
  ```

- [ ] **Step 3: Build Standard**

Run: `msbuild FC26-ZeroHook.sln /p:Configuration=Standard /p:Platform=x64`
Expected: clean build.

- [ ] **Step 4: Static verification**

Run: `strings.exe FC26Standard.dll | findstr /C:"[FBInput]" /C:"InputReader vtable not resolved" /C:"EPT hooks handle input blocking"`
Expected: **no hits** for any of these.

- [ ] **Step 5: Runtime smoke**

Inject into FC26. Expected in `zerohook.log`: a `[FBInput] reader=... isMouseDown=...` line and `[FBInput] Init OK ...` on success paths.

- [ ] **Step 6: Commit**

```bash
git add src/input/frostbite_input.cpp
git commit -m "input: encrypt frostbite input init log strings

Three FBInput init-time log messages are now compile-time encrypted."
```

---

### Task 8: Convert `src/offsets/offsets.cpp` — bulk sweep

The biggest Phase-1 file: 401 lines, ~30+ string literals, all at init time (called exactly once from `offsets::Init()`).

**Files:**
- Modify: `src/offsets/offsets.cpp`

- [ ] **Step 1: Enumerate every string literal**

Run (repo root):
```
grep -nE '"[^"]{3,}"' src/offsets/offsets.cpp
```

Save the output. Every quoted literal (log format strings, sig-scan pattern names, error tags) is a conversion target. Two exceptions:
- **Pattern byte strings** used as the `pattern` argument to `game::pattern_scan(...)` (e.g. `"E8 ? ? ? ? FF 23"`). These are search patterns used to find game offsets; they're effectively sig tokens. **Still convert them** — a reverser seeing `"48 89 3D ? ? ? ? 4C 89 35"` in IDA Strings immediately identifies the sig-scan style and the target.
- **Format specifier literals used as args to `log::debugf`** — these are `const char*` and convertible just like any other.

- [ ] **Step 2: Add the include**

At the top of `src/offsets/offsets.cpp`, add:

```cpp
#include "../crt/skcrypt.h"
```

- [ ] **Step 3: Apply the standard conversion pattern to every literal**

For each call like:

```cpp
log::debug("[offsets] [1/7] find_module()...\r\n");
```

replace with:

```cpp
{ auto s = skCrypt("[offsets] [1/7] find_module()...\r\n"); log::debug(s.decrypt()); s.clear(); }
```

For `log::debugf`:

```cpp
log::debugf("[offsets] [1/7] OK Game: %p  size=0x%lX\r\n", GameBase, GameSize);
```

→

```cpp
{ auto s = skCrypt("[offsets] [1/7] OK Game: %p  size=0x%lX\r\n"); log::debugf(s.decrypt(), GameBase, GameSize); s.clear(); }
```

For `game::pattern_scan`:

```cpp
void* gadgetMatch = game::pattern_scan(GameBase, GameSize, "E8 ? ? ? ? FF 23");
```

→

```cpp
void* gadgetMatch = nullptr;
{
    auto s = skCrypt("E8 ? ? ? ? FF 23");
    gadgetMatch = game::pattern_scan(GameBase, GameSize, s.decrypt());
    s.clear();
}
```

For conditional "OK"/"FAIL" strings inlined into a `debugf` argument list:

```cpp
log::debugf("[offsets] [2/7] %s SpoofLocation: %p\r\n",
    SpoofLocation ? "OK" : "FAIL", SpoofLocation);
```

→

```cpp
{
    auto sf  = skCrypt("[offsets] [2/7] %s SpoofLocation: %p\r\n");
    auto sok = skCrypt("OK");
    auto sfl = skCrypt("FAIL");
    log::debugf(sf.decrypt(), SpoofLocation ? sok.decrypt() : sfl.decrypt(), SpoofLocation);
    sf.clear(); sok.clear(); sfl.clear();
}
```

Apply the same transformation to every literal in the enumeration from Step 1. Work through the file top-to-bottom; do not skip any.

- [ ] **Step 4: Build Standard**

Run: `msbuild FC26-ZeroHook.sln /p:Configuration=Standard /p:Platform=x64`
Expected: clean build. (Scan the output for any `warning C4\d+` on lines you modified — MSVC sometimes warns on shadowed names if you reuse `s` across blocks in the same function; if so, rename the worst offenders to `s1`/`s2`.)

- [ ] **Step 5: Static verification**

Run (the specific tokens from the converted file):
```
strings.exe FC26Standard.dll | findstr /C:"[offsets]" /C:"SpoofLocation" /C:"SwapChain" /C:"InputReader" /C:"Spoof gadget pattern scan" /C:"pattern scan"
```

Expected: **no hits**.

Then run a broader check — take any 5 distinct plaintext fragments from your original enumeration (Step 1) and `findstr` for each. All must be absent.

- [ ] **Step 6: Runtime smoke — CRITICAL**

`offsets::Init()` is on the hot critical path of DllMain. If any of the sig-scan patterns got corrupted during conversion, `offsets::Init()` returns false and the DLL aborts injection (main.cpp line 24–26 `return TRUE` after the abort log).

Inject into FC26 with the game launched to the main menu. Expected in `zerohook.log`:
- `[ZeroHook] FC26-ZeroHook injected` (from main.cpp — confirms Task 5 still works)
- `[offsets] [1/7] OK Game: 0x... size=0x...` through `[offsets] [7/7] OK ...` — all seven phases report OK (or acceptable partial like `[3/7] FAIL (D3D not ready yet — normal at inject)`)

If any phase that previously said OK now says FAIL, the corresponding sig-scan pattern got mangled. Diff the converted `pattern_scan` call against its pre-conversion form.

- [ ] **Step 7: Commit**

```bash
git add src/offsets/offsets.cpp
git commit -m "offsets: encrypt all init-time strings via skCrypt

~30 log strings and pattern-scan tokens in offsets::Init() are now
compile-time encrypted. Includes sig-scan patterns like
'E8 ? ? ? ? FF 23' which are decrypted into stack buffers and
cleared after each pattern_scan call."
```

---

### Task 9: Phase-1 acceptance — full scan and DLL size delta

**Files:**
- No modifications. This is a verification-only task.

- [ ] **Step 1: Full-binary Phase-1 token scan**

Run (on Windows, output directory):
```
strings.exe FC26Standard.dll > phase1_strings.txt
findstr /I /C:"fc26.exe" /C:"fc26_trial" /C:"fc26_showcase" phase1_strings.txt
findstr /I /C:"FC26-ZeroHook injected" /C:"offsets::Init() failed" /C:"NtClose channel" phase1_strings.txt
findstr /I /C:"[offsets]" /C:"[FBInput]" /C:"boot:" phase1_strings.txt
findstr /C:"E8 ? ? ? ? FF 23" /C:"48 89 3D ? ? ? ? 4C 89 35" phase1_strings.txt
```

Expected: every `findstr` returns nothing (exit code 1). Any hit is a regression — trace it back to the source file and fix.

Repeat the same sequence against `FC26Premium.dll` (build Premium config first: `msbuild FC26-ZeroHook.sln /p:Configuration=Premium /p:Platform=x64`). The Premium DLL must be equally clean.

- [ ] **Step 2: IDA check**

Open `FC26Standard.dll` in IDA. Press `shift+F12`. In the filter box, try each of: `fc26`, `ZeroHook`, `offsets`, `boot:`, `FBInput`, `NtClose channel`.

Expected: zero matches for each filter.

- [ ] **Step 3: DLL size delta**

Before starting Task 1 (or retroactively from any pre-skcrypt build), record the baseline:
```
git checkout <commit-before-Task-1>
msbuild FC26-ZeroHook.sln /p:Configuration=Standard /p:Platform=x64
dir build\x64\Standard\FC26Standard.dll   # note the Size column
git checkout -   # return to Phase-1 head
```

Then compare post-Phase-1:
```
dir build\x64\Standard\FC26Standard.dll
```

Expected delta: within ~10 KB (additional encrypted blobs + small per-site decrypt stubs). A delta larger than ~50 KB suggests template instantiation blowup — review the disasm of one converted function in IDA to confirm the decrypt stub is small (~10–20 instructions per call site).

- [ ] **Step 4: Runtime gameplay acceptance**

Inject into FC26. Play through a brief flow that exercises each feature known to work pre-PR (per `memory/MEMORY.md`):
- Game launches, DLL loads, offsets resolve to all 7/7 OK (or documented partials).
- Menu opens (overlay renders).
- Toggle a known-good RosterSpoof feature (per `memory/roster_spoof_working_method.md` — the 11× `0xFAE6B64D` path) — confirm it still fires.
- Check `zerohook.log` — all converted log lines appear in decrypted plaintext.

Expected: no new crashes, no missing log output, all features work as before.

- [ ] **Step 5: Create a summary commit on the last converted file** (already done in Task 8) and push / PR if desired.

---

## Self-review notes

**Spec coverage:**
- "Plaintext of converted literals must not appear anywhere in `.rdata`" — covered by Task 2 Step 3, Task 4 Step 4, Task 5 Step 4, Task 6 Step 5, Task 7 Step 4, Task 8 Step 5, Task 9 Step 1/2.
- "Runtime decrypt-on-demand with explicit clear" — covered by every conversion task's code pattern.
- "Must compile cleanly under NOCRT, no exceptions, no RTTI, `/Zc:threadSafeInit-`" — covered: header uses no CRT symbols, no exceptions, no dynamic types.
- "No SIMD / no privileged instructions" — covered by `#pragma loop(no_vector)` and pure scalar XOR.
- "Kill-switch macro" — covered by Task 3.
- "Phase 1 rollout: main, offsets, game, comms, input" — Tasks 4–8. Remaining Phase-1 files in spec (`peb/peb.h` internal strings — has none; `hook/` install-time — mixed hot/cold so deferred to Phase 1B plan) are called out below.

**Explicit Phase-1 deferrals (tracked for a follow-up plan, not this one):**
- `hook/dxgi_hooks.cpp` install-time strings (file is 897 lines mixing install + per-frame; surgical conversion needs its own plan).
- `hook/network_hooks.cpp` install-time strings (661 lines; same reason).
- `bridge/pipe_server.h` init block (k32 export name strings).
- `bridge/memory_ops.h` init block (k32 export name strings).
- `renderer/renderer.cpp` init-only strings (`"d3d12.dll"`, `"D3D12SerializeRootSignature"` — rest of the file is per-frame and Phase 3).

These will land in a follow-up plan `2026-04-24-encrypted-strings-phase1b.md` (or similar) after this plan ships green.

**Risks:**
- `pattern_scan` takes the pattern as `const char*` in a synchronous call — decrypt → call → clear is safe. If `pattern_scan` ever becomes async (it's not today), the pattern for passing encrypted strings will need revisiting.
- Shadowed-variable warnings (`s` reused across blocks): MSVC `Level3` warnings are enabled. Block-scoping each conversion (via `{ ... }`) gives each `s` its own scope, so shadowing is not a problem — but if future callers drop the block scope, they'll hit it.
