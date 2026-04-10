#pragma once
#include <Windows.h>
#include "memory_ops.h"
#include "../log/fmt.h"

namespace bridge {

    struct Command {
        char cmd[16];
        char args[8][256];
        int  argCount;
    };

    // ── Parse "CMD:arg1:arg2\n" into Command struct ─────────────────────
    inline bool parseCommand(const char* input, int len, Command* out)
    {
        memZero(out, sizeof(Command));

        // Strip trailing \n or \r\n
        while (len > 0 && (input[len - 1] == '\n' || input[len - 1] == '\r'))
            len--;

        if (len <= 0) return false;

        // Extract command name (up to first ':' or end)
        int pos = 0;
        int cmdLen = 0;
        while (pos < len && input[pos] != ':' && cmdLen < 15) {
            out->cmd[cmdLen++] = input[pos++];
        }
        out->cmd[cmdLen] = '\0';

        // Parse colon-separated arguments
        out->argCount = 0;
        while (pos < len && out->argCount < 8) {
            if (input[pos] == ':') pos++; // skip ':'
            int argStart = pos;
            int argLen = 0;
            while (pos < len && input[pos] != ':' && argLen < 255) {
                out->args[out->argCount][argLen++] = input[pos++];
            }
            out->args[out->argCount][argLen] = '\0';
            if (argLen > 0) out->argCount++;
        }

        return cmdLen > 0;
    }

    // ── Build response: "OK:data\n" or "ERR:msg\n" ──────────────────────
    inline int buildResponse(char* buf, int max, bool ok, const char* data)
    {
        int pos = 0;
        const char* prefix = ok ? "OK" : "ERR";
        while (*prefix && pos < max - 1) buf[pos++] = *prefix++;

        if (data && data[0]) {
            if (pos < max - 1) buf[pos++] = ':';
            while (*data && pos < max - 1) buf[pos++] = *data++;
        }

        if (pos < max - 1) buf[pos++] = '\n';
        if (pos < max) buf[pos] = '\0';
        return pos;
    }

    // ── Process a command and write response ─────────────────────────────
    inline int processCommand(const Command* cmd, char* responseBuf, int responseMax, ScanState* scanState)
    {
        // PING
        if (strCmp(cmd->cmd, "PING") == 0) {
            return buildResponse(responseBuf, responseMax, true, "PONG");
        }

        // READ:addr:size
        if (strCmp(cmd->cmd, "READ") == 0) {
            if (cmd->argCount < 2)
                return buildResponse(responseBuf, responseMax, false, "BAD_ARGS");

            uintptr_t addr = parseHex(cmd->args[0], strLen(cmd->args[0]));
            int size = (int)parseHex(cmd->args[1], strLen(cmd->args[1]));

            if (addr < 0x10000)
                return buildResponse(responseBuf, responseMax, false, "BAD_ADDR");
            if (size <= 0 || size > 0x10000)
                return buildResponse(responseBuf, responseMax, false, "SIZE_LIMIT");

            // Read into temp buffer, then hex encode
            unsigned char tempBuf[0x10000];
            int bytesRead = readMemory(addr, tempBuf, size);
            if (bytesRead <= 0)
                return buildResponse(responseBuf, responseMax, false, "ACCESS_DENIED");

            char hexBuf[0x20002]; // 64K * 2 + nul
            hexEncode(tempBuf, bytesRead, hexBuf, sizeof(hexBuf));
            return buildResponse(responseBuf, responseMax, true, hexBuf);
        }

        // WRITE:addr:hexdata
        if (strCmp(cmd->cmd, "WRITE") == 0) {
            if (cmd->argCount < 2)
                return buildResponse(responseBuf, responseMax, false, "BAD_ARGS");

            uintptr_t addr = parseHex(cmd->args[0], strLen(cmd->args[0]));
            if (addr < 0x10000)
                return buildResponse(responseBuf, responseMax, false, "BAD_ADDR");

            int hexLen = strLen(cmd->args[1]);
            int dataSize = hexLen / 2;
            if (dataSize <= 0 || dataSize > 0x1000)
                return buildResponse(responseBuf, responseMax, false, "SIZE_LIMIT");

            unsigned char dataBuf[0x1000];
            int decoded = hexDecode(cmd->args[1], hexLen, dataBuf, sizeof(dataBuf));
            if (decoded < 0)
                return buildResponse(responseBuf, responseMax, false, "BAD_ARGS");

            int written = writeMemory(addr, dataBuf, decoded);
            if (written <= 0)
                return buildResponse(responseBuf, responseMax, false, "PROTECT_FAIL");

            char countBuf[16];
            fmt::snprintf(countBuf, sizeof(countBuf), "%X", (unsigned int)written);
            return buildResponse(responseBuf, responseMax, true, countBuf);
        }

        // SCAN_INIT:F32:value
        if (strCmp(cmd->cmd, "SCAN_INIT") == 0) {
            if (cmd->argCount < 2)
                return buildResponse(responseBuf, responseMax, false, "BAD_ARGS");

            // Only F32 supported in V1
            if (strCmp(cmd->args[0], "F32") != 0)
                return buildResponse(responseBuf, responseMax, false, "UNSUPPORTED_TYPE");

            float targetValue = parseFloat(cmd->args[1], strLen(cmd->args[1]));
            int count = scanInit(scanState, targetValue);

            char countBuf[16];
            fmt::snprintf(countBuf, sizeof(countBuf), "%X", (unsigned int)count);
            return buildResponse(responseBuf, responseMax, true, countBuf);
        }

        // SCAN_EXACT:F32:value
        if (strCmp(cmd->cmd, "SCAN_EXACT") == 0) {
            if (cmd->argCount < 2)
                return buildResponse(responseBuf, responseMax, false, "BAD_ARGS");

            float targetValue = parseFloat(cmd->args[1], strLen(cmd->args[1]));
            int count = scanExact(scanState, targetValue);

            char countBuf[16];
            fmt::snprintf(countBuf, sizeof(countBuf), "%X", (unsigned int)count);
            return buildResponse(responseBuf, responseMax, true, countBuf);
        }

        // SCAN_CHANGED
        if (strCmp(cmd->cmd, "SCAN_CHANGED") == 0) {
            int count = scanChanged(scanState);
            char countBuf[16];
            fmt::snprintf(countBuf, sizeof(countBuf), "%X", (unsigned int)count);
            return buildResponse(responseBuf, responseMax, true, countBuf);
        }

        // SCAN_UNCHANGED
        if (strCmp(cmd->cmd, "SCAN_UNCHANGED") == 0) {
            int count = scanUnchanged(scanState);
            char countBuf[16];
            fmt::snprintf(countBuf, sizeof(countBuf), "%X", (unsigned int)count);
            return buildResponse(responseBuf, responseMax, true, countBuf);
        }

        // SCAN_RESULTS[:max]
        if (strCmp(cmd->cmd, "SCAN_RESULTS") == 0) {
            int maxResults = 256;
            if (cmd->argCount >= 1 && strLen(cmd->args[0]) > 0)
                maxResults = (int)parseHex(cmd->args[0], strLen(cmd->args[0]));
            if (maxResults <= 0) maxResults = 256;
            if (maxResults > scanState->count) maxResults = scanState->count;

            char resultBuf[0x10000];
            int pos = 0;

            for (int i = 0; i < maxResults && pos < (int)sizeof(resultBuf) - 64; i++) {
                if (i > 0 && pos < (int)sizeof(resultBuf) - 1)
                    resultBuf[pos++] = ',';

                // addr=hexvalue
                char addrHex[20];
                fmt::snprintf(addrHex, sizeof(addrHex), "%llX", (unsigned long long)scanState->addresses[i]);
                for (int j = 0; addrHex[j] && pos < (int)sizeof(resultBuf) - 1; j++)
                    resultBuf[pos++] = addrHex[j];

                if (pos < (int)sizeof(resultBuf) - 1)
                    resultBuf[pos++] = '=';

                // Read current value and hex encode it
                float curVal = 0;
                __try { curVal = *(float*)scanState->addresses[i]; }
                __except (EXCEPTION_EXECUTE_HANDLER) { curVal = 0; }

                char valHex[16];
                hexEncode(&curVal, 4, valHex, sizeof(valHex));
                for (int j = 0; valHex[j] && pos < (int)sizeof(resultBuf) - 1; j++)
                    resultBuf[pos++] = valHex[j];
            }

            // Append remaining count if truncated
            int remaining = scanState->count - maxResults;
            if (remaining > 0) {
                char tail[32];
                fmt::snprintf(tail, sizeof(tail), "...%d_more", remaining);
                for (int j = 0; tail[j] && pos < (int)sizeof(resultBuf) - 1; j++)
                    resultBuf[pos++] = tail[j];
            }

            resultBuf[pos] = '\0';
            return buildResponse(responseBuf, responseMax, true, resultBuf);
        }

        // SCAN_RESET
        if (strCmp(cmd->cmd, "SCAN_RESET") == 0) {
            scanReset(scanState);
            return buildResponse(responseBuf, responseMax, true, nullptr);
        }

        return buildResponse(responseBuf, responseMax, false, "UNKNOWN_CMD");
    }

} // namespace bridge
