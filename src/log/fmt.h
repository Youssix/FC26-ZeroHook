#pragma once
#include <cstdarg>

namespace fmt
{
    namespace detail
    {
        inline int append_char(char* buf, int pos, int max, char c)
        {
            if (pos < max - 1) buf[pos] = c;
            return pos + 1;
        }

        inline int append_str(char* buf, int pos, int max, const char* s)
        {
            if (!s) s = "(null)";
            while (*s) pos = append_char(buf, pos, max, *s++);
            return pos;
        }

        inline int append_hex(char* buf, int pos, int max, unsigned long long val, int min_digits, bool upper)
        {
            const char* digits = upper ? "0123456789ABCDEF" : "0123456789abcdef";
            char tmp[17];
            int len = 0;
            if (val == 0) { tmp[len++] = '0'; }
            else { while (val) { tmp[len++] = digits[val & 0xF]; val >>= 4; } }
            while (len < min_digits) tmp[len++] = '0';
            for (int i = len - 1; i >= 0; i--)
                pos = append_char(buf, pos, max, tmp[i]);
            return pos;
        }

        inline int append_unsigned(char* buf, int pos, int max, unsigned long long val)
        {
            char tmp[21];
            int len = 0;
            if (val == 0) { tmp[len++] = '0'; }
            else { while (val) { tmp[len++] = '0' + (char)(val % 10); val /= 10; } }
            for (int i = len - 1; i >= 0; i--)
                pos = append_char(buf, pos, max, tmp[i]);
            return pos;
        }

        inline int append_signed(char* buf, int pos, int max, long long val)
        {
            if (val < 0) { pos = append_char(buf, pos, max, '-'); val = -val; }
            return append_unsigned(buf, pos, max, (unsigned long long)val);
        }
    }

    // Minimal snprintf: %s %p %u %d %x %X %lu %lX %llu %llX %02X %%
    inline int snprintf(char* buf, int max, const char* format, ...)
    {
        va_list args;
        va_start(args, format);

        int pos = 0;
        const char* p = format;

        while (*p)
        {
            if (*p != '%') { pos = detail::append_char(buf, pos, max, *p++); continue; }

            p++; // skip '%'

            // zero-pad width (only single digit supported: %02X etc.)
            int width = 0;
            bool zero_pad = false;
            if (*p == '0') { zero_pad = true; p++; }
            if (*p >= '1' && *p <= '9') { width = *p - '0'; p++; }
            else if (zero_pad && *p >= '1' && *p <= '9') { width = *p - '0'; p++; }
            (void)zero_pad; // width already implies zero-pad for hex

            // length modifier
            int long_count = 0;
            bool is_i64 = false;
            if (*p == 'l') { long_count++; p++; if (*p == 'l') { long_count++; p++; } }
            else if (*p == 'I' && *(p+1) == '6' && *(p+2) == '4') { is_i64 = true; p += 3; }

            bool is_64 = (long_count >= 2 || is_i64);

            switch (*p)
            {
            case 's':
                pos = detail::append_str(buf, pos, max, va_arg(args, const char*));
                break;
            case 'p': {
                void* ptr = va_arg(args, void*);
                pos = detail::append_hex(buf, pos, max, (unsigned long long)(uintptr_t)ptr, 16, true);
                break;
            }
            case 'X': case 'x': {
                bool upper = (*p == 'X');
                unsigned long long val = is_64 ? va_arg(args, unsigned long long) : va_arg(args, unsigned int);
                pos = detail::append_hex(buf, pos, max, val, width ? width : 1, upper);
                break;
            }
            case 'u': {
                unsigned long long val = is_64 ? va_arg(args, unsigned long long) : va_arg(args, unsigned int);
                pos = detail::append_unsigned(buf, pos, max, val);
                break;
            }
            case 'd': {
                long long val = is_64 ? va_arg(args, long long) : va_arg(args, int);
                pos = detail::append_signed(buf, pos, max, val);
                break;
            }
            case '%':
                pos = detail::append_char(buf, pos, max, '%');
                break;
            case '\0':
                goto done;
            default:
                pos = detail::append_char(buf, pos, max, '%');
                pos = detail::append_char(buf, pos, max, *p);
                break;
            }
            p++;
        }

    done:
        if (max > 0) buf[pos < max ? pos : max - 1] = '\0';
        va_end(args);
        return pos;
    }
}
