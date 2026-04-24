# Compile-time String Encryption (SkCrypt-style)

**Date:** 2026-04-24
**Status:** Approved — ready for implementation plan
**Target:** `FC26-ZeroHook.dll` (both `Standard` and `Premium` configurations)

## Problem

Opening `FC26Standard.dll` in IDA and viewing the Strings window (shift+F12) currently reveals ~425 plaintext literals, including feature names (`"RosterSpoof"`, `"AI Takeover"`), opcode log prefixes, EA/FIFA-specific tokens (`"fc26.exe"`), offset pattern names, and menu labels. These strings self-document the DLL for any reverse engineer — xrefs from `"RosterSpoof"` jump straight to the implementation. We want static analysis to stop being that cheap.

## Goals

- Plaintext of converted literals must not appear anywhere in `.rdata` or any other binary section.
- IDA's Strings window, `strings.exe`, and grep over the compiled DLL must find **zero** hits for converted literals.
- Runtime decrypt-on-demand with explicit clear, matching SkCrypt's API: `.decrypt()` / `.clear()`.
- Must compile cleanly under the project's existing constraints: NOCRT (`NOCRT_BUILD` define), MSVC v143, C++20, no exceptions, no RTTI, `/Zc:threadSafeInit-`, `BufferSecurityCheck=false`.
- Must not introduce any instruction that interacts with the `hvax64` hypervisor (no SIMD, no privileged instructions, no syscalls).

## Non-goals

- Defeating a runtime memory scanner that attaches mid-`.decrypt()`. Plaintext lives on the stack between `decrypt()` and `clear()`; that's inherent to SkCrypt-style and out of scope here.
- Encrypting every string on day one. Hot paths (per-frame renderer, per-tick logs) are deferred to a later phase.
- Encrypting D3D12 input-layout array initializers (`"POSITION"`, `"TEXCOORD"`) that are passed as `LPCSTR` pointers into static `D3D12_INPUT_ELEMENT_DESC[]` arrays. Those need a different treatment and are low-value for anti-RE anyway.

## Design

### Header — `src/crt/skcrypt.h`

A single header that exposes two macros:

```cpp
auto s = skCrypt("some text");   // char variant
auto w = skCryptW(L"fc26.exe");  // wchar_t variant

const char*    p = s.decrypt();  // returns pointer to in-place decrypted stack buffer
const wchar_t* q = w.decrypt();

s.clear();                       // overwrite the stack buffer with zeros
w.clear();
```

**Internals (bare-C style — no STL, no `<type_traits>`, no `<utility>`):**

- A single template struct `sk::holder<CharT, N>` with `CharT buf[N]` and a 4-byte rolling `key[4]`. Trivially copyable POD — no ctors/dtors/vtables, no exception metadata.
- A `consteval` factory `sk::build<CharT, N>(const CharT (&src)[N], unsigned k)` that encrypts at compile time. Because it is `consteval`, MSVC must evaluate at compile time — the source literal never makes it into `.rdata`. Only the encrypted holder does.
- `decrypt()` XORs `buf[i]` in place with `key[i & 3]` and returns the pointer. Single-use per holder — calling `decrypt()` twice in a row re-encrypts to ciphertext (XOR is its own inverse). Expected usage is `decrypt() → use → clear()`; classic SkCrypt semantics.
- `clear()` zeros `buf[i]` via `volatile` writes so MSVC can't optimize the wipe away.
- Key derivation combines `__COUNTER__`, `__LINE__`, and a fixed build salt (`0xC0FFEE42`). Two identical literals in different call sites encrypt to different ciphertext — no dedup tell.
- `#pragma loop(no_vector)` on the decrypt loop to prevent auto-vectorization to SSE2 — keeps codegen scalar for hypervisor-safety.

**Kill-switch:** `#define SKCRYPT_DISABLE` at the top of the header. When defined, `skCrypt(x)` becomes a no-op wrapper that returns `x` unchanged with stub `.decrypt()`/`.clear()`. Lets us bisect a regression without ripping out call sites.

**NOCRT compliance:** header does not call `memcpy`, `memset`, or any other CRT symbol. All work is plain integer XOR in `for` loops over `CharT buf[N]`. MSVC will not emit `__security_check_cookie` (disabled project-wide), `__chkstk` (buffers are <1 page), or `memcpy` intrinsic (no struct-copy wider than the holder itself).

### Build integration

- No `.vcxproj` changes. Header-only, uses already-enabled C++20 `consteval`.
- Both `Standard` and `Premium` configurations get real encryption. No per-config flag yet (YAGNI).
- Each converted TU adds `#include "../crt/skcrypt.h"` (relative path that matches that directory's existing include style).
- `skCrypt` / `skCryptW` macros are global; implementation lives in `namespace sk { ... }`.

### Rollout plan (phased, cold-paths first)

**Phase 1 — init-time / "done once" (first implementation PR after the header lands):**
- `main.cpp` (DllMain, bootstrap)
- `offsets/offsets.cpp` + `.h` (sig-scan pattern names, module names)
- `peb/peb.h` (export resolution — `"NtClose"`, `"ntdll.dll"`, etc.)
- `game/game.cpp` (the `L"fc26.exe"` / `L"fc26_trial.exe"` / `L"fc26_showcase.exe"` array)
- `comms/comms.cpp` init
- `hook/` install-time strings (hook target names, not per-invocation)
- `input/frostbite_input.cpp` init

**Phase 2 — event-driven, cold (one PR per module):**
- `features/*.cpp` — button-press opcode sends, feature names
- `menu/overlay.cpp` — UI labels built once per menu open
- `menu/toast.h` — toast messages (user-triggered)
- `bridge/protocol.h` — pipe tokens (low frequency)

**Phase 3 — hot paths (evaluated after Phase 2 based on runtime impact):**
- `renderer/renderer.cpp`, `hook/dxgi_hooks.cpp` per-frame log call sites
- `log::debug` / `log::debugf` call sites on per-frame paths
- D3D12 input-layout semantic names — need a separate design (these are array-initializer `LPCSTR` pointers, not isolated literals)

### Verification (per-phase acceptance)

Project has no unit-test harness (NOCRT DLL, no test runner). Verification is binary + runtime:

1. **Static (the real acceptance test):**
   - Phase 1 grep: `strings.exe FC26Standard.dll | grep -iE "fc26|fc26_trial|fc26_showcase|NtClose|ntdll"` returns zero hits. Each subsequent phase adds its converted tokens to the grep list and re-runs.
   - IDA shift+F12 search for the same tokens finds nothing.
   - Spot-check a converted xref — the function that previously xrefed a plaintext literal now xrefs only an encrypted blob.
2. **Runtime smoke:**
   - Inject into FC26: game launches, DLL loads, offsets resolve, menu appears, known-good features (roster spoof, sliders, console-only spoof) still work.
   - Log file output for converted `log::debug` calls must show correct plaintext (proves `.decrypt()` is lossless).
3. **DLL size delta:** post-PR size is within a few KB of pre-PR (one encrypted blob per literal + one small scalar XOR stub per call site). A 100+ KB bump signals template-instantiation blowup.

## Decisions locked

| Decision | Choice |
|---|---|
| Threat model | Static analysis (IDA string view, `strings.exe`). Runtime dumps out of scope. |
| API surface | `skCrypt("...")` / `skCryptW(L"...")` → `.decrypt()` / `.clear()` |
| Implementation | Custom ~80-line header written against this project's constraints. Not vendored SkCrypt (pulls `std::array`/`<type_traits>` in some forks, needs NOCRT audit) and not JM-XorStr (uses SSE/AVX intrinsics — rejected on hypervisor-safety grounds). |
| Scope | All cold-path strings; hot paths deferred. Phase 1 = "done once at init". |
| Build configs | Both `Standard` and `Premium` encrypt. No per-config flag. |
| Kill-switch | `SKCRYPT_DISABLE` macro at header top |
| CRT compliance | No CRT symbols used. Scalar XOR loop only. `#pragma loop(no_vector)`. |
| Hypervisor compliance | No SIMD, no privileged instructions. Scalar byte XOR. |

## Open follow-ups (not part of this spec)

- After Phase 2 ships: measure per-frame overhead if Phase 3 is pursued.
- If we later want Standard-only encryption (dev-builds leave strings readable for faster iteration), wire `SKCRYPT_DISABLE` off `STANDARD_BUILD` vs. `PREMIUM_BUILD`.
- If static entropy becomes a pattern-match signal (e.g. an anti-cheat starts fingerprinting the scalar XOR decrypt stub shape), we swap the internals for something SIMD-free but more varied (per-site random op sequences) — call sites don't change because the macro name stays `skCrypt(...)`.
