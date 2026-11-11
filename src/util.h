#ifndef AEGIS_UTIL_H
#define AEGIS_UTIL_H

#include <stddef.h>
#include <stdint.h>

/* All decoders return 0 on success, -1 on invalid input. */

/* Standard base64 with optional whitespace and padding. Result is malloc'ed. */
int base64_decode(const char *in, unsigned char **out, size_t *outlen);

/* RFC 4648 base32 (A-Z, 2-7), case-insensitive, spaces and '-' ignored. */
int base32_decode(const char *in, unsigned char *out, size_t outcap, size_t *outlen);

/* Decodes exactly outlen bytes from a 2*outlen character hex string. */
int hex_decode_exact(const char *in, unsigned char *out, size_t outlen);

/* Overwrites memory in a way the compiler will not optimize away. */
void secure_wipe(void *ptr, size_t size);

#endif
