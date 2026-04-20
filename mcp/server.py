"""
zerohook-bridge MCP server

Connects to the DLL's named pipe (\\.\pipe\zerohook-{GAME}) and exposes
memory read/write/scan tools to Claude Code via the MCP stdio transport.
"""

from mcp.server.fastmcp import FastMCP
import struct

# Try to import pywin32 - only available on Windows
try:
    import win32file
    import win32api
    import pywintypes
    WINDOWS = True
except ImportError:
    WINDOWS = False

mcp = FastMCP("zerohook-bridge")

KNOWN_GAMES = ["BF1", "FC26", "BF4", "BFV", "BF2042"]

# --- Pipe client state ---

pipe_handle = None
connected_game = None

NOT_CONNECTED_MSG = "Not connected to any game. Use connect_game() first."


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _pipe_name(game: str) -> str:
    return rf"\\.\pipe\zerohook-{game}"


def _find_pipes() -> list[str]:
    """Return list of game names with active zerohook pipes."""
    found = []
    if not WINDOWS:
        return found
    for game in KNOWN_GAMES:
        try:
            h = win32file.CreateFile(
                _pipe_name(game),
                win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                0, None,
                win32file.OPEN_EXISTING,
                0, None,
            )
            win32file.CloseHandle(h)
            found.append(game)
        except Exception:
            pass
    return found


def _connect(game_name: str) -> None:
    """Connect to a zerohook pipe. Raises on failure."""
    global pipe_handle, connected_game
    if not WINDOWS:
        raise RuntimeError("pywin32 not available (not running on Windows)")
    h = win32file.CreateFile(
        _pipe_name(game_name),
        win32file.GENERIC_READ | win32file.GENERIC_WRITE,
        0, None,
        win32file.OPEN_EXISTING,
        0, None,
    )
    pipe_handle = h
    connected_game = game_name


def _send_command(cmd: str) -> str:
    """
    Send a command to the DLL and return the response data string.

    Raises RuntimeError on ERR: responses or pipe failures.
    """
    global pipe_handle, connected_game

    if pipe_handle is None:
        raise RuntimeError(NOT_CONNECTED_MSG)

    try:
        win32file.WriteFile(pipe_handle, (cmd + "\n").encode("ascii"))
        data = b""
        while not data.endswith(b"\n"):
            _, chunk = win32file.ReadFile(pipe_handle, 65536)
            data += chunk
        response = data.decode("ascii").rstrip("\n")
    except Exception as e:
        # Pipe disconnected
        pipe_handle = None
        connected_game = None
        raise RuntimeError(f"Game disconnected. Reconnect with connect_game(). ({e})")

    if response.startswith("OK:"):
        return response[3:]
    elif response == "OK":
        return ""
    elif response.startswith("ERR:"):
        raise RuntimeError(f"DLL error: {response[4:]}")
    else:
        raise RuntimeError(f"Unexpected response: {response!r}")


# ---------------------------------------------------------------------------
# Hex dump formatting
# ---------------------------------------------------------------------------

def _is_valid_pointer(val: int) -> bool:
    """True if value looks like a valid userspace pointer."""
    return 0x10000 <= val <= 0x7FFFFFFFFFFF


def _looks_like_float(raw: bytes) -> bool:
    """True if the 4-byte value has a float exponent in a 'reasonable' range."""
    if len(raw) < 4:
        return False
    # Extract exponent bits (bits 23-30)
    i = struct.unpack_from("<I", raw)[0]
    exp = (i >> 23) & 0xFF
    # Exponents 0x38 (=56) to 0x48 (=72) correspond to ~1e-5 to ~1e5
    return 0x38 <= exp <= 0x48


def _format_hex_dump(base_addr: int, raw: bytes) -> str:
    """
    Format raw bytes as a rich annotated hex dump.

    Each 16-byte row:
      +0x00: AA BB CC DD EE FF 00 11  22 33 44 55 66 77 88 99  | f32: (v0, v1, v2, v3) | ptr: XXXX [valid]
    """
    lines = []
    for row_off in range(0, len(raw), 16):
        chunk = raw[row_off: row_off + 16]
        addr = base_addr + row_off

        # Hex bytes with a gap between bytes 8 and 9
        hex_parts = []
        for i, b in enumerate(chunk):
            if i == 8:
                hex_parts.append(" ")
            hex_parts.append(f"{b:02X}")
        hex_str = " ".join(hex_parts) if len(chunk) == 16 else " ".join(f"{b:02X}" for b in chunk)
        # Pad to fixed width (16 bytes = 16*3-1 + 1 gap = 48 chars)
        hex_display = " ".join(f"{b:02X}" for b in chunk[:8])
        if len(chunk) > 8:
            hex_display += "  " + " ".join(f"{b:02X}" for b in chunk[8:])
        hex_display = hex_display.ljust(49)

        # Float annotations for each 4-byte group
        float_vals = []
        for fi in range(0, len(chunk), 4):
            fb = chunk[fi: fi + 4]
            if len(fb) == 4:
                (fv,) = struct.unpack_from("<f", fb)
                if _looks_like_float(fb):
                    float_vals.append(f"{fv:.4f}")
                else:
                    float_vals.append(f"({fv:.2e})")

        float_str = ""
        if float_vals:
            float_str = "f32: (" + ", ".join(float_vals) + ")"

        # Pointer annotation for the first 8-byte value in the row
        ptr_str = ""
        if len(chunk) >= 8:
            (ptr_val,) = struct.unpack_from("<Q", chunk[:8])
            if _is_valid_pointer(ptr_val):
                ptr_str = f"ptr: {ptr_val:016X} [valid]"

        # Build row
        parts = [f"0x{addr:X} +{row_off:#06x}: {hex_display}"]
        if float_str:
            parts.append(f"| {float_str}")
        if ptr_str:
            parts.append(f"| {ptr_str}")
        lines.append("  ".join(parts))

    return "\n".join(lines)


def _format_dump_struct(base_addr: int, raw: bytes) -> str:
    """
    Richer per-qword annotation: pointer check, float pair, int pair, ASCII.
    Used by dump_struct.
    """
    lines = []
    for row_off in range(0, len(raw), 8):
        chunk = raw[row_off: row_off + 8]
        addr = base_addr + row_off

        hex_str = " ".join(f"{b:02X}" for b in chunk).ljust(23)

        annots = []

        # Pointer
        if len(chunk) == 8:
            (ptr_val,) = struct.unpack_from("<Q", chunk)
            if _is_valid_pointer(ptr_val):
                annots.append(f"ptr {ptr_val:016X} [valid heap]")
            else:
                annots.append(f"ptr {ptr_val:016X}")

        # Float pair
        if len(chunk) >= 8:
            f0, f1 = struct.unpack_from("<ff", chunk)
            annots.append(f"f32: ({f0:.4f}, {f1:.4f})")

        # Int pair
        if len(chunk) >= 8:
            i0, i1 = struct.unpack_from("<ii", chunk)
            annots.append(f"i32: ({i0}, {i1})")

        # ASCII
        ascii_repr = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
        annots.append(f"ascii: {ascii_repr}")

        annot_str = "  ".join(annots)
        lines.append(f"0x{addr:X} +{row_off:#06x}: {hex_str}  {annot_str}")

    return "\n".join(lines)


def _normalize_address(address: str) -> str:
    """Strip 0x prefix and uppercase the address string."""
    addr = address.strip()
    if addr.lower().startswith("0x"):
        addr = addr[2:]
    return addr.upper()


def _parse_scan_results(data: str, scan_type: str = "F32") -> str:
    """
    Parse SCAN_RESULTS response data and format as a readable table.
    data: "addr1=hexval,addr2=hexval,...[...N_more]"
    """
    if not data:
        return "No results."

    # Split off trailing "...N_more" note
    trailing = ""
    if "..." in data:
        idx = data.rfind(",...")
        if idx == -1:
            idx = data.find("...")
        if idx != -1:
            trailing = data[idx:]
            data = data[:idx]

    entries = [e for e in data.split(",") if "=" in e]
    lines = []
    for entry in entries:
        addr_hex, val_hex = entry.split("=", 1)
        try:
            raw = bytes.fromhex(val_hex)
            if scan_type == "F32" and len(raw) >= 4:
                (fv,) = struct.unpack_from("<f", raw)
                lines.append(f"  0x{addr_hex}  =  {fv:.6f}  ({val_hex})")
            elif scan_type in ("I32", "U32") and len(raw) >= 4:
                (iv,) = struct.unpack_from("<i" if scan_type == "I32" else "<I", raw)
                lines.append(f"  0x{addr_hex}  =  {iv}  ({val_hex})")
            else:
                lines.append(f"  0x{addr_hex}  =  {val_hex}")
        except Exception:
            lines.append(f"  0x{addr_hex}  =  {val_hex}")

    result = "\n".join(lines)
    if trailing:
        result += f"\n  {trailing}"
    return result


# ---------------------------------------------------------------------------
# MCP Tools
# ---------------------------------------------------------------------------

@mcp.tool()
def connect_game(game_name: str = "") -> str:
    """Connect to a game's zerohook bridge pipe.

    If no game_name given, auto-discovers active pipes and connects to the
    first one found.

    Args:
        game_name: Game name (e.g., 'BF1', 'BF4'). Leave empty to auto-discover.
    """
    global pipe_handle, connected_game

    if not WINDOWS:
        return "ERROR: pywin32 is not installed or this is not Windows. Install with: pip install pywin32"

    # Disconnect existing handle if any
    if pipe_handle is not None:
        try:
            win32file.CloseHandle(pipe_handle)
        except Exception:
            pass
        pipe_handle = None
        connected_game = None

    if game_name:
        try:
            _connect(game_name)
            return f"Connected to zerohook-{game_name}"
        except Exception as e:
            return f"Failed to connect to zerohook-{game_name}: {e}"

    # Auto-discover
    found = _find_pipes()
    if not found:
        return (
            "No ZeroHook pipes found. Is the DLL loaded?\n"
            f"Checked: {', '.join(f'zerohook-{g}' for g in KNOWN_GAMES)}"
        )
    if len(found) == 1:
        try:
            _connect(found[0])
            return f"Auto-connected to zerohook-{found[0]}"
        except Exception as e:
            return f"Found zerohook-{found[0]} but failed to connect: {e}"

    # Multiple found - connect to first, inform user
    try:
        _connect(found[0])
        others = ", ".join(f"zerohook-{g}" for g in found[1:])
        return (
            f"Auto-connected to zerohook-{found[0]}.\n"
            f"Other active pipes: {others}\n"
            "Use connect_game(game_name=...) to switch."
        )
    except Exception as e:
        return f"Found {found} but failed to connect: {e}"


@mcp.tool()
def ping() -> str:
    """Check if the bridge is connected to a game."""
    if pipe_handle is None:
        return NOT_CONNECTED_MSG
    try:
        data = _send_command("PING")
        return f"Connected to zerohook-{connected_game}: {data}"
    except RuntimeError as e:
        return str(e)


@mcp.tool()
def read_memory(address: str, size: int = 64) -> str:
    """Read memory from the game process and return an annotated hex dump.

    Args:
        address: Hex address (e.g., '0x1437F8758' or '1437F8758')
        size: Number of bytes to read (default 64, max 65536)
    """
    if pipe_handle is None:
        return NOT_CONNECTED_MSG

    size = min(size, 65536)
    addr = _normalize_address(address)

    try:
        data = _send_command(f"READ:{addr}:{size:X}")
    except RuntimeError as e:
        return str(e)

    try:
        raw = bytes.fromhex(data)
    except ValueError:
        return f"Failed to parse response hex: {data!r}"

    base = int(addr, 16)
    header = f"read_memory(0x{base:X}, {size}) -> {len(raw)} bytes\n"
    return header + _format_hex_dump(base, raw)


@mcp.tool()
def write_memory(address: str, hex_bytes: str) -> str:
    """Write bytes to a game memory address.

    Args:
        address: Hex address (e.g., '0x1437F8758' or '1437F8758')
        hex_bytes: Hex-encoded bytes to write (e.g., '0000803F' for float 1.0)
    """
    if pipe_handle is None:
        return NOT_CONNECTED_MSG

    addr = _normalize_address(address)
    # Normalize hex bytes: strip spaces, uppercase
    hb = hex_bytes.replace(" ", "").upper()

    try:
        data = _send_command(f"WRITE:{addr}:{hb}")
    except RuntimeError as e:
        return str(e)

    try:
        written = int(data, 16)
        return f"Wrote {written} bytes to 0x{addr}"
    except ValueError:
        return f"Write OK: {data}"


@mcp.tool()
def scan_float(value: float, module: str = "") -> str:
    """Start a new scan for a float (F32) value in game memory.

    Args:
        value: Float value to search for
        module: Optional module name to restrict scan (e.g., 'bf1.exe')
    """
    if pipe_handle is None:
        return NOT_CONNECTED_MSG

    cmd = f"SCAN_INIT:F32:{value}"
    if module:
        cmd += f":{module}"

    try:
        data = _send_command(cmd)
    except RuntimeError as e:
        return str(e)

    try:
        count = int(data, 16)
    except ValueError:
        count = data

    scope = f" in {module}" if module else ""
    return f"Scan for F32={value}{scope}: {count} candidates found."


@mcp.tool()
def scan_exact(value: float) -> str:
    """Filter scan results: keep only addresses matching this exact float value.

    Args:
        value: Float value to match
    """
    if pipe_handle is None:
        return NOT_CONNECTED_MSG
    try:
        data = _send_command(f"SCAN_EXACT:F32:{value}")
    except RuntimeError as e:
        return str(e)
    try:
        count = int(data, 16)
    except ValueError:
        count = data
    return f"SCAN_EXACT F32={value}: {count} candidates remaining."


@mcp.tool()
def scan_changed() -> str:
    """Filter scan results: keep only addresses whose value changed since last scan."""
    if pipe_handle is None:
        return NOT_CONNECTED_MSG
    try:
        data = _send_command("SCAN_CHANGED")
    except RuntimeError as e:
        return str(e)
    try:
        count = int(data, 16)
    except ValueError:
        count = data
    return f"SCAN_CHANGED: {count} candidates remaining."


@mcp.tool()
def scan_unchanged() -> str:
    """Filter scan results: keep only addresses whose value stayed the same."""
    if pipe_handle is None:
        return NOT_CONNECTED_MSG
    try:
        data = _send_command("SCAN_UNCHANGED")
    except RuntimeError as e:
        return str(e)
    try:
        count = int(data, 16)
    except ValueError:
        count = data
    return f"SCAN_UNCHANGED: {count} candidates remaining."


@mcp.tool()
def scan_results(max_count: int = 50) -> str:
    """Get current scan results (addresses + values).

    Args:
        max_count: Maximum number of results to return (default 50)
    """
    if pipe_handle is None:
        return NOT_CONNECTED_MSG
    try:
        data = _send_command(f"SCAN_RESULTS:{max_count:X}")
    except RuntimeError as e:
        return str(e)
    return _parse_scan_results(data, "F32")


@mcp.tool()
def scan_reset() -> str:
    """Reset the current scan and free all candidate memory."""
    if pipe_handle is None:
        return NOT_CONNECTED_MSG
    try:
        _send_command("SCAN_RESET")
    except RuntimeError as e:
        return str(e)
    return "Scan reset."


@mcp.tool()
def dump_struct(address: str, size: int = 256) -> str:
    """Dump a structure with detailed per-qword annotations.

    Each 8-byte row shows: pointer check, float pair, int pair, and ASCII.
    Useful for reverse engineering unknown struct layouts.

    Args:
        address: Hex address (e.g., '0x1437F8758')
        size: Number of bytes to dump (default 256)
    """
    if pipe_handle is None:
        return NOT_CONNECTED_MSG

    size = min(size, 65536)
    addr = _normalize_address(address)

    try:
        data = _send_command(f"READ:{addr}:{size:X}")
    except RuntimeError as e:
        return str(e)

    try:
        raw = bytes.fromhex(data)
    except ValueError:
        return f"Failed to parse response hex: {data!r}"

    base = int(addr, 16)
    header = f"dump_struct(0x{base:X}, {size}) -> {len(raw)} bytes\n"
    return header + _format_dump_struct(base, raw)


@mcp.tool()
def get_module_base(module_name: str = "bf1.exe") -> str:
    """Get the base address of the game module.

    Note: DLL doesn't support MODULES command. Returns known base addresses.

    Args:
        module_name: Module name (default 'bf1.exe')
    """
    # Known bases from PEB walk in DLL init
    known = {
        "bf1.exe": 0x140000000,
    }
    base = known.get(module_name.lower())
    if base:
        return f"{module_name} base: 0x{base:X}"
    return f"Unknown module: {module_name}. Known: {', '.join(known.keys())}"


# ---------------------------------------------------------------------------
# Convenience readers / writers
# ---------------------------------------------------------------------------

def _read_raw(address: str, size: int) -> bytes:
    """Read raw bytes from game memory. Raises on failure."""
    addr = _normalize_address(address)
    data = _send_command(f"READ:{addr}:{size:X}")
    return bytes.fromhex(data)


@mcp.tool()
def read_float(address: str) -> str:
    """Read a single 32-bit float from memory.

    Args:
        address: Hex address
    """
    if pipe_handle is None:
        return NOT_CONNECTED_MSG
    try:
        raw = _read_raw(address, 4)
        val = struct.unpack_from("<f", raw)[0]
        return f"0x{_normalize_address(address)}: {val:.6f}"
    except Exception as e:
        return str(e)


@mcp.tool()
def read_int(address: str, signed: bool = True) -> str:
    """Read a 32-bit integer from memory.

    Args:
        address: Hex address
        signed: If True, interpret as signed int32 (default True)
    """
    if pipe_handle is None:
        return NOT_CONNECTED_MSG
    try:
        raw = _read_raw(address, 4)
        fmt = "<i" if signed else "<I"
        val = struct.unpack_from(fmt, raw)[0]
        return f"0x{_normalize_address(address)}: {val} (0x{val & 0xFFFFFFFF:08X})"
    except Exception as e:
        return str(e)


@mcp.tool()
def read_qword(address: str) -> str:
    """Read a 64-bit value (pointer / uint64) from memory.

    Args:
        address: Hex address
    """
    if pipe_handle is None:
        return NOT_CONNECTED_MSG
    try:
        raw = _read_raw(address, 8)
        val = struct.unpack_from("<Q", raw)[0]
        tag = " [valid ptr]" if _is_valid_pointer(val) else ""
        return f"0x{_normalize_address(address)}: 0x{val:016X}{tag}"
    except Exception as e:
        return str(e)


@mcp.tool()
def read_vec3(address: str) -> str:
    """Read a Vec3 (3 floats: x, y, z) from memory.

    Args:
        address: Hex address of the first float
    """
    if pipe_handle is None:
        return NOT_CONNECTED_MSG
    try:
        raw = _read_raw(address, 12)
        x, y, z = struct.unpack_from("<fff", raw)
        return f"0x{_normalize_address(address)}: ({x:.4f}, {y:.4f}, {z:.4f})"
    except Exception as e:
        return str(e)


@mcp.tool()
def read_vec4(address: str) -> str:
    """Read a Vec4 (4 floats: x, y, z, w) from memory.

    Args:
        address: Hex address of the first float
    """
    if pipe_handle is None:
        return NOT_CONNECTED_MSG
    try:
        raw = _read_raw(address, 16)
        x, y, z, w = struct.unpack_from("<ffff", raw)
        return f"0x{_normalize_address(address)}: ({x:.4f}, {y:.4f}, {z:.4f}, {w:.4f})"
    except Exception as e:
        return str(e)


@mcp.tool()
def read_pointer_chain(base: str, offsets: list[int]) -> str:
    """Follow a multi-level pointer chain and return every step.

    Reads [base] then follows each offset: [[base]+off0]+off1]+...
    Shows the full chain with values at each level.

    Args:
        base: Starting hex address (e.g., '0x1437F8758')
        offsets: List of integer offsets to follow (e.g., [0, 0x68, 0x1D48])
    """
    if pipe_handle is None:
        return NOT_CONNECTED_MSG

    lines = [f"Chain: base=0x{_normalize_address(base)}"]
    try:
        addr = int(_normalize_address(base), 16)
        for i, off in enumerate(offsets):
            raw = _read_raw(f"{addr:X}", 8)
            val = struct.unpack_from("<Q", raw)[0]
            tag = "[valid]" if _is_valid_pointer(val) else "[INVALID]"
            lines.append(f"  [{i}] [0x{addr:X}] = 0x{val:016X} {tag}")
            if not _is_valid_pointer(val):
                lines.append(f"  CHAIN BROKEN at step {i}")
                return "\n".join(lines)
            addr = val + off
            lines.append(f"       + 0x{off:X} = 0x{addr:X}")
        # Read final value as both qword and float
        raw = _read_raw(f"{addr:X}", 8)
        qval = struct.unpack_from("<Q", raw)[0]
        fval = struct.unpack_from("<f", raw)[0]
        lines.append(f"  => Final address: 0x{addr:X}")
        lines.append(f"     as qword: 0x{qval:016X}")
        lines.append(f"     as float: {fval:.6f}")
    except Exception as e:
        lines.append(f"  ERROR: {e}")
    return "\n".join(lines)


@mcp.tool()
def write_float(address: str, value: float) -> str:
    """Write a 32-bit float to memory.

    Args:
        address: Hex address
        value: Float value to write
    """
    if pipe_handle is None:
        return NOT_CONNECTED_MSG
    try:
        hb = struct.pack("<f", value).hex().upper()
        addr = _normalize_address(address)
        _send_command(f"WRITE:{addr}:{hb}")
        return f"Wrote {value:.6f} to 0x{addr}"
    except Exception as e:
        return str(e)


@mcp.tool()
def write_int(address: str, value: int) -> str:
    """Write a 32-bit integer to memory.

    Args:
        address: Hex address
        value: Integer value to write
    """
    if pipe_handle is None:
        return NOT_CONNECTED_MSG
    try:
        hb = struct.pack("<i", value).hex().upper()
        addr = _normalize_address(address)
        _send_command(f"WRITE:{addr}:{hb}")
        return f"Wrote {value} to 0x{addr}"
    except Exception as e:
        return str(e)


@mcp.tool()
def write_qword(address: str, value: str) -> str:
    """Write a 64-bit value to memory.

    Args:
        address: Hex address
        value: Hex value to write (e.g., '0x141370CB0')
    """
    if pipe_handle is None:
        return NOT_CONNECTED_MSG
    try:
        ival = int(_normalize_address(value), 16)
        hb = struct.pack("<Q", ival).hex().upper()
        addr = _normalize_address(address)
        _send_command(f"WRITE:{addr}:{hb}")
        return f"Wrote 0x{ival:016X} to 0x{addr}"
    except Exception as e:
        return str(e)


@mcp.tool()
def write_nop(address: str, count: int = 1) -> str:
    """Write NOP (0x90) bytes to memory. Useful for patching instructions.

    Args:
        address: Hex address
        count: Number of NOP bytes to write (default 1)
    """
    if pipe_handle is None:
        return NOT_CONNECTED_MSG
    try:
        hb = "90" * count
        addr = _normalize_address(address)
        _send_command(f"WRITE:{addr}:{hb}")
        return f"Wrote {count} NOPs to 0x{addr}"
    except Exception as e:
        return str(e)


# ---------------------------------------------------------------------------
# Scan extensions
# ---------------------------------------------------------------------------

@mcp.tool()
def scan_int_value(value: int, struct_address: str = "", struct_size: int = 0x5000) -> str:
    """Search for a 32-bit integer value inside a struct's memory range.

    Uses READ + Python-side comparison (DLL only supports F32 scan natively).

    Args:
        value: Integer value to search for
        struct_address: Base address of struct to search in (required)
        struct_size: How many bytes to scan (default 0x5000)
    """
    if pipe_handle is None:
        return NOT_CONNECTED_MSG
    if not struct_address:
        return "struct_address is required (DLL does not support global I32 scan)"

    base = int(_normalize_address(struct_address), 16)
    matches = []
    chunk_size = 4096

    try:
        for chunk_off in range(0, struct_size, chunk_size):
            read_size = min(chunk_size, struct_size - chunk_off)
            raw = _read_raw(f"{base + chunk_off:X}", read_size)
            for i in range(0, len(raw) - 3, 4):
                iv = struct.unpack_from("<i", raw, i)[0]
                if iv == value:
                    offset = chunk_off + i
                    matches.append(f"  +0x{offset:04X} (0x{base + offset:X}) = {iv}")
    except Exception as e:
        matches.append(f"  ERROR: {e}")

    header = f"scan_int_value({value}, 0x{base:X}, 0x{struct_size:X})\n"
    if matches:
        return header + f"{len(matches)} matches:\n" + "\n".join(matches[:50])
    return header + "No matches found."


# ---------------------------------------------------------------------------
# Multi-read / watch tools
# ---------------------------------------------------------------------------

@mcp.tool()
def watch_address(address: str, data_type: str = "float", count: int = 10, interval_ms: int = 200) -> str:
    """Read an address repeatedly to observe changes over time.

    Useful for finding values that change during gameplay (recoil, spread, velocity).
    NOTE: Reads happen sequentially from Python — game continues running between reads.

    Args:
        address: Hex address to watch
        data_type: 'float', 'int', or 'qword'
        count: Number of samples (default 10)
        interval_ms: Milliseconds between samples (default 200)
    """
    if pipe_handle is None:
        return NOT_CONNECTED_MSG

    import time
    addr = _normalize_address(address)
    size = 4 if data_type in ("float", "int") else 8

    samples = []
    try:
        for i in range(count):
            raw = _read_raw(addr, size)
            if data_type == "float":
                val = struct.unpack_from("<f", raw)[0]
                samples.append(f"  t={i * interval_ms}ms: {val:.6f}")
            elif data_type == "int":
                val = struct.unpack_from("<i", raw)[0]
                samples.append(f"  t={i * interval_ms}ms: {val}")
            else:
                val = struct.unpack_from("<Q", raw)[0]
                samples.append(f"  t={i * interval_ms}ms: 0x{val:016X}")
            if i < count - 1:
                time.sleep(interval_ms / 1000.0)
    except Exception as e:
        samples.append(f"  ERROR: {e}")

    header = f"watch_address(0x{addr}, {data_type}, {count} samples, {interval_ms}ms)\n"
    return header + "\n".join(samples)


@mcp.tool()
def compare_snapshots(addresses: list[str], data_type: str = "float", delay_ms: int = 2000) -> str:
    """Take two snapshots of multiple addresses with a delay between them.

    Shows which values changed — useful for finding recoil/spread/velocity during firing.
    Instruct the user to perform an action (fire, move, ADS) during the delay.

    Args:
        addresses: List of hex addresses to monitor
        data_type: 'float' or 'int'
        delay_ms: Delay between snapshots in ms (default 2000 — user acts during this)
    """
    if pipe_handle is None:
        return NOT_CONNECTED_MSG

    import time
    size = 4

    # Snapshot 1
    snap1 = {}
    for a in addresses:
        addr = _normalize_address(a)
        try:
            raw = _read_raw(addr, size)
            if data_type == "float":
                snap1[addr] = struct.unpack_from("<f", raw)[0]
            else:
                snap1[addr] = struct.unpack_from("<i", raw)[0]
        except Exception:
            snap1[addr] = None

    # Wait
    time.sleep(delay_ms / 1000.0)

    # Snapshot 2 + compare
    lines = [f"compare_snapshots({len(addresses)} addrs, {delay_ms}ms delay)\n"]
    changed = 0
    for a in addresses:
        addr = _normalize_address(a)
        try:
            raw = _read_raw(addr, size)
            if data_type == "float":
                v2 = struct.unpack_from("<f", raw)[0]
            else:
                v2 = struct.unpack_from("<i", raw)[0]
        except Exception:
            v2 = None

        v1 = snap1.get(addr)
        if v1 is not None and v2 is not None:
            if data_type == "float":
                delta = abs(v2 - v1)
                if delta > 0.0001:
                    lines.append(f"  0x{addr}: {v1:.6f} -> {v2:.6f} (delta={v2 - v1:+.6f}) CHANGED")
                    changed += 1
            else:
                if v1 != v2:
                    lines.append(f"  0x{addr}: {v1} -> {v2} CHANGED")
                    changed += 1

    lines.append(f"\n{changed}/{len(addresses)} addresses changed.")
    return "\n".join(lines)


@mcp.tool()
def scan_struct_for_value(base_address: str, value: float, struct_size: int = 0x5000, tolerance: float = 0.05) -> str:
    """Scan a struct's memory range for a specific float value.

    Useful for finding where a known value (yaw, health, speed) is stored inside an object.

    Args:
        base_address: Start address of the struct
        value: Float value to search for
        struct_size: How many bytes to scan (default 0x5000)
        tolerance: Allowed difference from target value (default 0.05)
    """
    if pipe_handle is None:
        return NOT_CONNECTED_MSG

    base = int(_normalize_address(base_address), 16)
    matches = []
    chunk_size = 4096  # read in chunks

    try:
        for chunk_off in range(0, struct_size, chunk_size):
            read_size = min(chunk_size, struct_size - chunk_off)
            raw = _read_raw(f"{base + chunk_off:X}", read_size)
            for i in range(0, len(raw) - 3, 4):
                fv = struct.unpack_from("<f", raw, i)[0]
                if abs(fv - value) <= tolerance:
                    offset = chunk_off + i
                    matches.append(f"  +0x{offset:04X} (0x{base + offset:X}) = {fv:.6f}")
    except Exception as e:
        matches.append(f"  ERROR at offset 0x{chunk_off:X}: {e}")

    header = f"scan_struct_for_value(0x{base:X}, {value:.4f}, size=0x{struct_size:X})\n"
    if matches:
        return header + f"{len(matches)} matches:\n" + "\n".join(matches[:50])
    return header + "No matches found."


@mcp.tool()
def scan_struct_for_pointer(base_address: str, struct_size: int = 0x200) -> str:
    """List all valid-looking pointers inside a struct.

    Reads qwords and checks if they look like valid heap/module pointers.
    Useful for mapping unknown struct layouts.

    Args:
        base_address: Start address of the struct
        struct_size: How many bytes to scan (default 0x200)
    """
    if pipe_handle is None:
        return NOT_CONNECTED_MSG

    base = int(_normalize_address(base_address), 16)
    results = []

    try:
        raw = _read_raw(f"{base:X}", struct_size)
        for off in range(0, len(raw) - 7, 8):
            val = struct.unpack_from("<Q", raw, off)[0]
            if _is_valid_pointer(val):
                # Check if it's in module range
                tag = "module" if 0x140000000 <= val <= 0x155000000 else "heap"
                results.append(f"  +0x{off:04X}: 0x{val:016X} [{tag}]")
    except Exception as e:
        results.append(f"  ERROR: {e}")

    header = f"scan_struct_for_pointer(0x{base:X}, 0x{struct_size:X})\n"
    if results:
        return header + f"{len(results)} pointers:\n" + "\n".join(results)
    return header + "No valid pointers found."


# ---------------------------------------------------------------------------
# Watchpoints (NtClose → kernel implant → hypervisor SLAT/EPT)
# ---------------------------------------------------------------------------
#
# Hardware-style watchpoints with no sticky breakpoint, no DR usage, no in-page
# code modification. Set on physical pages via the hypervisor's SLAT — guest
# can't see them at all. Useful for tracing what writes a state field, who
# emits a network opcode, etc.
#
# Requires the hypervisor + kernel implant to be loaded on the target box. If
# they're not, install/remove return NO_IMPLANT_OR_FAIL.

# Access mask bits — see WATCHPOINT_ACCESS_* in src/bridge/watchpoint_ops.h
WATCH_R = 1
WATCH_W = 2
WATCH_X = 4

# Sentinel: follow the cr3_tracker's target process (handles KPTI / cloned CR3
# transparently). Pass anything else (or 0 for off, or a raw CR3 PFN).
WATCH_FILTER_TRACKER = 0xFFFFFFFFFFFFFFFF


def _parse_access_mask(access: str) -> int:
    """Parse 'r', 'w', 'x', 'rw', 'rwx' etc. into the bit mask."""
    a = access.lower().strip()
    mask = 0
    if "r" in a: mask |= WATCH_R
    if "w" in a: mask |= WATCH_W
    if "x" in a: mask |= WATCH_X
    return mask


def _decode_event(hex_blob: str) -> dict:
    """Decode one hex-encoded watchpoint_event_t (256 hex chars / 128 bytes)."""
    raw = bytes.fromhex(hex_blob)
    if len(raw) != 128:
        return {"error": f"bad event size {len(raw)}"}
    (tsc, rip, gcr3, gva, gpa) = struct.unpack_from("<QQQQQ", raw, 0)
    (access_type, wp_id, cpu_id) = struct.unpack_from("<IHH", raw, 40)
    (rax, rcx, rdx, rbx, rsp, rbp, rsi, rdi) = struct.unpack_from("<8Q", raw, 48)
    access_str = {0: "R", 1: "W", 2: "X"}.get(access_type, f"?{access_type}")
    return {
        "tsc": tsc, "rip": rip, "cr3": gcr3,
        "gva": gva, "gpa": gpa,
        "access": access_str, "wp_id": wp_id, "cpu": cpu_id,
        "rax": rax, "rcx": rcx, "rdx": rdx, "rbx": rbx,
        "rsp": rsp, "rbp": rbp, "rsi": rsi, "rdi": rdi,
    }


@mcp.tool()
def watch_install(address: str, access: str = "rw", length: int = 1,
                  filter_tracker: bool = True, count_only: bool = False) -> str:
    """Install a hypervisor watchpoint on a guest virtual address.

    No sticky breakpoint, no DR registers — uses the hypervisor's SLAT to trap
    accesses transparently. Requires the kernel implant to be loaded.

    Args:
        address: Hex VA to watch (e.g., '0x14D8953F8' for matchCtx field).
        access: Any combo of 'r', 'w', 'x' (e.g., 'rw', 'x', 'w').
        length: Bytes to watch starting at address (1..4096, must stay in page).
        filter_tracker: If True, only fire when CR3 matches cr3_tracker's
            target process. If False, fire for all CR3s (noisy).
        count_only: If True, count hits without recording full events
            (cheaper, no ring usage).

    Returns watchpoint id on success, or an error message.
    """
    if pipe_handle is None:
        return NOT_CONNECTED_MSG

    mask = _parse_access_mask(access)
    if mask == 0:
        return f"BAD ACCESS: {access!r} (use any of 'r','w','x')"
    if length < 1 or length > 4096:
        return f"BAD LENGTH: {length} (must be 1..4096)"

    addr = _normalize_address(address)
    addr_int = int(addr, 16)
    # Guard against straddling a page boundary — hypervisor watchpoints are
    # per-page; offset+length must stay within 4096.
    page_off = addr_int & 0xFFF
    if page_off + length > 4096:
        return (f"WATCH range straddles page boundary "
                f"(page_off=0x{page_off:X} + length={length} > 4096). "
                "Split into multiple watchpoints.")

    cr3 = WATCH_FILTER_TRACKER if filter_tracker else 0
    co  = 1 if count_only else 0

    try:
        data = _send_command(
            f"WATCH_INSTALL:{addr}:{mask:X}:{length:X}:{cr3:X}:{co:X}"
        )
    except RuntimeError as e:
        return str(e)

    try:
        wp_id = int(data, 16)
    except ValueError:
        return f"Unexpected response: {data!r}"

    return (f"watchpoint installed: id={wp_id} va=0x{addr} mask=0x{mask:X} "
            f"({access}) length={length} "
            f"filter={'tracker' if filter_tracker else 'off'} "
            f"count_only={count_only}")


@mcp.tool()
def watch_remove(watchpoint_id: int) -> str:
    """Remove a previously installed watchpoint.

    Args:
        watchpoint_id: ID returned by watch_install.
    """
    if pipe_handle is None:
        return NOT_CONNECTED_MSG
    if watchpoint_id <= 0:
        return f"BAD ID: {watchpoint_id}"

    try:
        data = _send_command(f"WATCH_REMOVE:{watchpoint_id:X}")
    except RuntimeError as e:
        return str(e)
    return f"watchpoint id={watchpoint_id} removed ({data})"


@mcp.tool()
def watch_drain(max_events: int = 64) -> str:
    """Drain watchpoint events from the current CPU's ring.

    The hypervisor uses per-CPU ring buffers — drain returns events recorded
    on whichever CPU happens to service the syscall (kernel implant runs on
    the calling thread's CPU). For comprehensive coverage you may need to pin
    the bridge thread to specific CPUs and drain each in turn.

    Args:
        max_events: Maximum events to return (default 64, hard cap 256).

    Returns a formatted table of events: tsc, rip, cr3, access, gva, gpa, regs.
    """
    if pipe_handle is None:
        return NOT_CONNECTED_MSG

    cap = max(1, min(int(max_events), 256))

    try:
        data = _send_command(f"WATCH_DRAIN:{cap:X}")
    except RuntimeError as e:
        return str(e)

    parts = data.split(",")
    if not parts or parts[0] == "":
        return "watch_drain: empty response"

    try:
        count = int(parts[0], 16)
    except ValueError:
        return f"watch_drain: bad count {parts[0]!r}"

    if count == 0:
        return "watch_drain: 0 events"

    events = []
    for blob in parts[1:1 + count]:
        try:
            events.append(_decode_event(blob))
        except Exception as e:
            events.append({"error": str(e)})

    lines = [f"watch_drain: {count} event(s)"]
    for i, ev in enumerate(events):
        if "error" in ev:
            lines.append(f"  [{i:3d}] DECODE_ERR: {ev['error']}")
            continue
        lines.append(
            f"  [{i:3d}] wp={ev['wp_id']} cpu={ev['cpu']} {ev['access']} "
            f"rip=0x{ev['rip']:016X} cr3=0x{ev['cr3']:X} "
            f"gva=0x{ev['gva']:X} gpa=0x{ev['gpa']:X}"
        )
        lines.append(
            f"        rax={ev['rax']:016X} rcx={ev['rcx']:016X} "
            f"rdx={ev['rdx']:016X} rbx={ev['rbx']:016X}"
        )
    return "\n".join(lines)


@mcp.tool()
def watch_stats(watchpoint_id: int) -> str:
    """Get hit/dropped counters for a watchpoint.

    Args:
        watchpoint_id: ID returned by watch_install.
    """
    if pipe_handle is None:
        return NOT_CONNECTED_MSG
    if watchpoint_id <= 0:
        return f"BAD ID: {watchpoint_id}"

    try:
        data = _send_command(f"WATCH_STATS:{watchpoint_id:X}")
    except RuntimeError as e:
        return str(e)

    parts = data.split(",")
    if len(parts) != 2:
        return f"watch_stats: unexpected response {data!r}"
    try:
        hits    = int(parts[0], 16)
        dropped = int(parts[1], 16)
    except ValueError:
        return f"watch_stats: bad numbers {data!r}"

    return f"watchpoint id={watchpoint_id}: hits={hits} dropped={dropped}"


# ---------------------------------------------------------------------------
# Execute breakpoints (EPT hooks → C detour in bridge DLL → ring buffer)
# ---------------------------------------------------------------------------
#
# Each BP captures full register state + 4 stack frames + a TSC timestamp.
# Slot count is fixed (64 in the bridge); ring is 1024 events. Drain returns
# the latest N events in chronological order.
#
# Detection profile: single E9 patched into the EPT exec view, no INT3, no
# DR usage, no Win32 alloc. Stub page lives in hypervisor-managed runtime
# heap invisible to guest scans.

BP_EVENT_HEX_LEN = 384  # 192 bytes * 2


def _decode_bp_event(hex_blob: str) -> dict:
    """Decode one hex-encoded bp_event_t (384 hex chars / 192 bytes)."""
    raw = bytes.fromhex(hex_blob)
    if len(raw) != 192:
        return {"error": f"bad event size {len(raw)}"}
    (tsc, target_va, original_rsp, rflags) = struct.unpack_from("<QQQQ", raw, 0)
    (rax, rcx, rdx, rbx, rbp, rsi, rdi)    = struct.unpack_from("<7Q", raw, 32)
    (r8, r9, r10, r11, r12, r13, r14, r15) = struct.unpack_from("<8Q", raw, 88)
    stack = list(struct.unpack_from("<4Q", raw, 152))
    (bp_id, cpu_id, _reserved)             = struct.unpack_from("<HHI", raw, 184)
    return {
        "tsc": tsc, "target_va": target_va,
        "rsp": original_rsp, "rflags": rflags,
        "rax": rax, "rcx": rcx, "rdx": rdx, "rbx": rbx,
        "rbp": rbp, "rsi": rsi, "rdi": rdi,
        "r8": r8, "r9": r9, "r10": r10, "r11": r11,
        "r12": r12, "r13": r13, "r14": r14, "r15": r15,
        "stack": stack, "bp_id": bp_id, "cpu_id": cpu_id,
    }


@mcp.tool()
def bp_install(target: str, module: str = "", count_only: bool = False) -> str:
    """Install an execute breakpoint via EPT hook in the bridge DLL.

    Two ways to specify the address:
      bp_install("0x14282BB00")                    — absolute VA
      bp_install("0x282BB00", module="FC26.exe")   — module-relative RVA

    Module-relative is recommended for anything that should survive game
    updates (the bridge resolves the base via PEB walk at install time).

    Args:
        target: Absolute VA, OR an RVA when module is set. Hex with or
            without leading 0x.
        module: Optional module name (e.g. "FC26.exe"). When set, target
            is treated as an RVA added to the resolved module base.
        count_only: If True, every hit only bumps the counter (no ring
            entry). Use for hot functions where you just want a hit-rate.

    Returns: "BP installed: id=N target=0x..." on success.
    """
    if pipe_handle is None:
        return NOT_CONNECTED_MSG

    co = "1" if count_only else "0"
    addr = _normalize_address(target)

    if module:
        cmd = f"BP_INSTALL:{module}:{addr}:{co}"
    else:
        cmd = f"BP_INSTALL:{addr}:{co}"

    try:
        data = _send_command(cmd)
    except RuntimeError as e:
        return str(e)

    parts = data.split(",")
    if len(parts) < 2:
        return f"BP install: unexpected response {data!r}"
    try:
        bp_id  = int(parts[0], 16)
        ptr_va = int(parts[1], 16)
    except ValueError:
        return f"BP install: bad numbers {data!r}"

    return (f"BP installed: id={bp_id} target=0x{ptr_va:016X} "
            f"{'(count-only)' if count_only else '(full capture)'}")


@mcp.tool()
def bp_remove(bp_id: int) -> str:
    """Disable a breakpoint and free its slot. The EPT shadow page stays
    patched but the wrapper short-circuits via the disabled flag — zero
    observable effect on the game from there on.

    Args:
        bp_id: The id returned by bp_install.
    """
    if pipe_handle is None:
        return NOT_CONNECTED_MSG
    if bp_id <= 0:
        return f"BAD ID: {bp_id}"
    try:
        _send_command(f"BP_REMOVE:{bp_id:X}")
        return f"BP id={bp_id} removed"
    except RuntimeError as e:
        return str(e)


@mcp.tool()
def bp_enable(bp_id: int, enabled: bool = True) -> str:
    """Toggle a BP without removing it. Cheap — just flips a flag the
    wrapper reads. Use this to silence a noisy hot-function BP between
    drains.

    Args:
        bp_id: The id returned by bp_install.
        enabled: True to enable (capture hits), False to silence.
    """
    if pipe_handle is None:
        return NOT_CONNECTED_MSG
    if bp_id <= 0:
        return f"BAD ID: {bp_id}"
    val = "1" if enabled else "0"
    try:
        data = _send_command(f"BP_ENABLE:{bp_id:X}:{val}")
        return f"BP id={bp_id}: {data}"
    except RuntimeError as e:
        return str(e)


@mcp.tool()
def bp_drain(max_events: int = 64) -> str:
    """Return the latest N captured BP events in chronological order.

    Each event has: tsc, target_va, rip-equivalent, rsp, rflags, all 16
    GPRs, top 4 return addresses on the stack, bp_id, cpu_id.

    Args:
        max_events: Up to 256 per call (hard cap). Default 64.
    """
    if pipe_handle is None:
        return NOT_CONNECTED_MSG

    cap = max(1, min(int(max_events), 256))
    try:
        data = _send_command(f"BP_DRAIN:{cap:X}")
    except RuntimeError as e:
        return str(e)

    parts = data.split(",")
    if not parts or parts[0] == "":
        return "bp_drain: empty response"
    try:
        count = int(parts[0], 16)
    except ValueError:
        return f"bp_drain: bad count {parts[0]!r}"
    if count == 0:
        return "bp_drain: 0 events captured since last install/drain"

    events = []
    for blob in parts[1:1 + count]:
        try:
            events.append(_decode_bp_event(blob))
        except Exception as e:
            events.append({"error": str(e)})

    lines = [f"bp_drain: {count} event(s)"]
    for i, ev in enumerate(events):
        if "error" in ev:
            lines.append(f"  [{i:3d}] DECODE_ERR: {ev['error']}")
            continue
        stack_str = " → ".join(f"0x{ra:X}" for ra in ev["stack"] if ra)
        lines.append(
            f"  [{i:3d}] bp={ev['bp_id']} tsc={ev['tsc']} "
            f"@0x{ev['target_va']:016X} "
            f"rcx=0x{ev['rcx']:X} rdx=0x{ev['rdx']:X} "
            f"r8=0x{ev['r8']:X} r9=0x{ev['r9']:X}"
        )
        lines.append(
            f"        rsp=0x{ev['rsp']:X} rflags=0x{ev['rflags']:X}"
        )
        if stack_str:
            lines.append(f"        callers: {stack_str}")
    return "\n".join(lines)


@mcp.tool()
def bp_stats(bp_id: int) -> str:
    """Show hit/dropped counters and current enabled state for a BP.

    Args:
        bp_id: The id returned by bp_install.
    """
    if pipe_handle is None:
        return NOT_CONNECTED_MSG
    if bp_id <= 0:
        return f"BAD ID: {bp_id}"
    try:
        data = _send_command(f"BP_STATS:{bp_id:X}")
    except RuntimeError as e:
        return str(e)
    parts = data.split(",")
    if len(parts) != 3:
        return f"bp_stats: unexpected response {data!r}"
    try:
        hits    = int(parts[0], 16)
        dropped = int(parts[1], 16)
        enabled = int(parts[2]) != 0
    except ValueError:
        return f"bp_stats: bad numbers {data!r}"
    return (f"BP id={bp_id}: hits={hits} dropped={dropped} "
            f"{'ENABLED' if enabled else 'disabled'}")


# ---------------------------------------------------------------------------
# Pattern scan (AOB) — find code by signature, survives ASLR + game updates
# ---------------------------------------------------------------------------

@mcp.tool()
def scan_pattern(module: str, pattern: str) -> str:
    """Find the first byte sequence in a loaded module's memory.

    Pattern syntax: hex bytes separated by spaces, '??' (or '?') for
    wildcards. The bridge walks the module's image (PE SizeOfImage range)
    starting from its loaded base and returns the first match VA.

    Examples:
        scan_pattern("FC26.exe", "48 89 5C 24 ?? 57 48 83 EC 20")
        scan_pattern("FC26.exe", "48 8D 0D ?? ?? ?? ?? E8")

    Args:
        module: Module name (e.g. "FC26.exe", "ntdll.dll").
        pattern: Space-separated hex bytes with '??' for wildcards.
    """
    if pipe_handle is None:
        return NOT_CONNECTED_MSG
    if not module or not pattern:
        return "BAD ARGS"

    # Args go through colon-separated parser; pattern uses spaces, no colons.
    try:
        data = _send_command(f"SCAN_PATTERN:{module}:{pattern}")
    except RuntimeError as e:
        return str(e)

    try:
        va = int(data, 16)
    except ValueError:
        return f"scan_pattern: unexpected response {data!r}"

    return f"scan_pattern: 0x{va:016X}  ({module} + 0x{va:X})"


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Attempt auto-connect on startup
    if WINDOWS:
        found = _find_pipes()
        if len(found) == 1:
            try:
                _connect(found[0])
                print(f"[zerohook-bridge] Auto-connected to zerohook-{found[0]}", flush=True)
            except Exception as e:
                print(f"[zerohook-bridge] Auto-connect failed: {e}", flush=True)
        elif len(found) > 1:
            print(f"[zerohook-bridge] Multiple pipes found: {found}. Use connect_game() to select.", flush=True)
        else:
            print("[zerohook-bridge] No zerohook pipes found. Use connect_game() after injecting the DLL.", flush=True)

    mcp.run()
