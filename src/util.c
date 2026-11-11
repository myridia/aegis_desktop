#include "util.h"

#include <stdlib.h>
#include <string.h>

/*---------------------------------------------------------------------------*/

static int i_b64_value(const char c)
{
    if (c >= 'A' && c <= 'Z')
        return c - 'A';
    if (c >= 'a' && c <= 'z')
        return c - 'a' + 26;
    if (c >= '0' && c <= '9')
        return c - '0' + 52;
    if (c == '+')
        return 62;
    if (c == '/')
        return 63;
    return -1;
}

/*---------------------------------------------------------------------------*/

static int i_b64_space(const char c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

/*---------------------------------------------------------------------------*/

int base64_decode(const char *in, unsigned char **out, size_t *outlen)
{
    size_t len;
    size_t i;
    size_t used = 0;
    unsigned char *buf;
    int quad[4];
    int qn = 0;

    if (in == NULL || out == NULL || outlen == NULL)
        return -1;

    len = strlen(in);
    buf = (unsigned char *)malloc(len / 4 * 3 + 4);
    if (buf == NULL)
        return -1;

    for (i = 0; i < len; i += 1)
    {
        char c = in[i];
        int v;

        if (i_b64_space(c))
            continue;
        if (c == '=')
            break;

        v = i_b64_value(c);
        if (v < 0)
        {
            free(buf);
            return -1;
        }

        quad[qn++] = v;
        if (qn == 4)
        {
            buf[used++] = (unsigned char)((quad[0] << 2) | (quad[1] >> 4));
            buf[used++] = (unsigned char)(((quad[1] & 0x0F) << 4) | (quad[2] >> 2));
            buf[used++] = (unsigned char)(((quad[2] & 0x03) << 6) | quad[3]);
            qn = 0;
        }
    }

    if (qn == 1)
    {
        free(buf);
        return -1;
    }
    else if (qn == 2)
    {
        buf[used++] = (unsigned char)((quad[0] << 2) | (quad[1] >> 4));
    }
    else if (qn == 3)
    {
        buf[used++] = (unsigned char)((quad[0] << 2) | (quad[1] >> 4));
        buf[used++] = (unsigned char)(((quad[1] & 0x0F) << 4) | (quad[2] >> 2));
    }

    *out = buf;
    *outlen = used;
    return 0;
}

/*---------------------------------------------------------------------------*/

int base32_decode(const char *in, unsigned char *out, size_t outcap, size_t *outlen)
{
    uint32_t acc = 0;
    int bits = 0;
    size_t used = 0;

    if (in == NULL || out == NULL || outlen == NULL)
        return -1;

    while (*in != '\0')
    {
        int c = (unsigned char)*in;
        int v;

        if (c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '-')
        {
            in += 1;
            continue;
        }
        if (c == '=')
            break;

        if (c >= 'A' && c <= 'Z')
            v = c - 'A';
        else if (c >= 'a' && c <= 'z')
            v = c - 'a';
        else if (c >= '2' && c <= '7')
            v = c - '2' + 26;
        else
            return -1;

        acc = (acc << 5) | (uint32_t)v;
        bits += 5;

        if (bits >= 8)
        {
            bits -= 8;
            if (used >= outcap)
                return -1;
            out[used++] = (unsigned char)((acc >> bits) & 0xFF);
        }

        in += 1;
    }

    *outlen = used;
    return 0;
}

/*---------------------------------------------------------------------------*/

static int i_hex_value(const char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

/*---------------------------------------------------------------------------*/

int hex_decode_exact(const char *in, unsigned char *out, size_t outlen)
{
    size_t i;

    if (in == NULL || out == NULL)
        return -1;
    if (strlen(in) != outlen * 2)
        return -1;

    for (i = 0; i < outlen; i += 1)
    {
        int hi = i_hex_value(in[i * 2]);
        int lo = i_hex_value(in[i * 2 + 1]);
        if (hi < 0 || lo < 0)
            return -1;
        out[i] = (unsigned char)((hi << 4) | lo);
    }

    return 0;
}

/*---------------------------------------------------------------------------*/

void secure_wipe(void *ptr, size_t size)
{
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (size > 0)
    {
        *p++ = 0;
        size -= 1;
    }
}
