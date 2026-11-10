#ifndef AEGIS_OTP_H
#define AEGIS_OTP_H

#include <stddef.h>
#include <stdint.h>

typedef enum
{
    OTP_TOTP = 0,
    OTP_HOTP,
    OTP_STEAM
} otp_kind_t;

/*
 * Generates an OTP code.
 *
 * key/keylen   raw shared secret
 * algo         "SHA1", "SHA256" or "SHA512" (NULL means SHA1)
 * kind         TOTP/HOTP digits 4..10; Steam always 5 characters
 * digits       number of digits (ignored for Steam)
 * counter      moving factor (TOTP time step or HOTP counter)
 * out/outlen   output buffer (at least 16 bytes is enough)
 *
 * Returns 0 on success, -1 on error.
 */
int otp_generate(const unsigned char *key, size_t keylen, const char *algo,
                 otp_kind_t kind, int digits, uint64_t counter,
                 char *out, size_t outlen);

#endif
