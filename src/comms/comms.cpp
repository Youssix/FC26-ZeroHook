#include "comms.h"
#include "../log/log.h"
#include "../log/fmt.h"

bool comms::test_channel()
{
    implant_request_t req = {};
    req.command = CMD_PING;

    ntclose_syscall(NTCLOSE_MAGIC, (unsigned long long)&req);

    char buf[128];
    fmt::snprintf(buf, sizeof(buf), "[Ring-1] Ping: status=%u, result=0x%llX\r\n", req.status, req.result);
    log::to_file(buf);

    if (req.status == 0 && req.result == 0xACE)
    {
        log::to_file("[Ring-1] NtClose channel OK\r\n");
        return true;
    }

    log::to_file("[Ring-1] NtClose channel FAILED\r\n");
    return false;
}
