#ifndef AEGIS_VAULT_H
#define AEGIS_VAULT_H

#include <stddef.h>

#include "otp.h"

#define VAULT_OK 0
#define VAULT_ERROR 1
#define VAULT_NEED_PASSWORD 2
#define VAULT_BAD_PASSWORD 3

typedef struct
{
    char *issuer;
    char *name;
    otp_kind_t kind;
    char algo[8];
    int digits;
    int period;
    unsigned long long counter;
    unsigned char *secret;
    size_t secret_len;
} otp_entry_t;

typedef struct
{
    otp_entry_t *entries;
    size_t count;
    size_t skipped;
} vault_t;

/*
 * Loads an Aegis Authenticator export.
 *
 * password == NULL reads a plain export. If the file is encrypted the function
 * returns VAULT_NEED_PASSWORD. A wrong password/corrupted tag returns
 * VAULT_BAD_PASSWORD.
 *
 * 'vault' is only modified on VAULT_OK. Call vault_free() when done.
 */
int vault_load(const char *path, const char *password, vault_t *vault,
               char *err, size_t errlen);

void vault_free(vault_t *vault);

#endif
