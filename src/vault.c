#include "vault.h"

#include "json.h"
#include "util.h"

#include <openssl/evp.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#define MAX_FILE_SIZE (64u * 1024u * 1024u)
#define MAX_ENTRIES 20000u

#define GCM_NONCE_SIZE 12u
#define GCM_TAG_SIZE 16u
#define KEY_SIZE 32u
#define SALT_SIZE 32u

/*---------------------------------------------------------------------------*/

static void i_set_error(char *err, size_t errlen, const char *message)
{
    if (err != NULL && errlen > 0)
        snprintf(err, errlen, "%s", message);
}

/*---------------------------------------------------------------------------*/

static int i_read_file(const char *path, char **text, size_t *textlen,
                       char *err, size_t errlen)
{
    FILE *file;
    long length;
    char *buffer;
    size_t got;

    *text = NULL;
    *textlen = 0;

    file = fopen(path, "rb");
    if (file == NULL)
    {
        i_set_error(err, errlen, "Cannot open the selected file.");
        return -1;
    }

    if (fseek(file, 0, SEEK_END) != 0)
    {
        fclose(file);
        i_set_error(err, errlen, "Cannot read the selected file.");
        return -1;
    }

    length = ftell(file);
    if (length < 0)
    {
        fclose(file);
        i_set_error(err, errlen, "Cannot determine the file size.");
        return -1;
    }

    if ((unsigned long)length > MAX_FILE_SIZE)
    {
        fclose(file);
        i_set_error(err, errlen, "The file is too large to be an Aegis export.");
        return -1;
    }

    if (fseek(file, 0, SEEK_SET) != 0)
    {
        fclose(file);
        i_set_error(err, errlen, "Cannot read the selected file.");
        return -1;
    }

    buffer = (char *)malloc((size_t)length + 1);
    if (buffer == NULL)
    {
        fclose(file);
        i_set_error(err, errlen, "Out of memory.");
        return -1;
    }

    got = fread(buffer, 1, (size_t)length, file);
    fclose(file);

    if (got != (size_t)length)
    {
        secure_wipe(buffer, got);
        free(buffer);
        i_set_error(err, errlen, "Cannot read the selected file.");
        return -1;
    }

    buffer[got] = '\0';
    *text = buffer;
    *textlen = got;
    return 0;
}

/*---------------------------------------------------------------------------*/

static char *i_dup_string(const char *text)
{
    size_t len = text != NULL ? strlen(text) : 0;
    char *copy = (char *)malloc(len + 1);
    if (copy == NULL)
        return NULL;
    if (len > 0)
        memcpy(copy, text, len);
    copy[len] = '\0';
    return copy;
}

/*---------------------------------------------------------------------------*/

static int i_algo_name(const char *algo, char out[8])
{
    if (algo == NULL)
    {
        strcpy(out, "SHA1");
        return 0;
    }
    if (strcasecmp(algo, "SHA1") == 0)
    {
        strcpy(out, "SHA1");
        return 0;
    }
    if (strcasecmp(algo, "SHA256") == 0)
    {
        strcpy(out, "SHA256");
        return 0;
    }
    if (strcasecmp(algo, "SHA512") == 0)
    {
        strcpy(out, "SHA512");
        return 0;
    }
    return -1;
}

/*---------------------------------------------------------------------------*/

static int i_parse_entries(const Json *db, vault_t *vault, char *err, size_t errlen)
{
    const Json *entries = json_object_get(db, "entries");
    size_t count;
    size_t cap;
    size_t i;

    if (json_type(entries) != JSON_ARRAY)
    {
        i_set_error(err, errlen, "This is not an Aegis export (no 'entries' array).");
        return -1;
    }

    count = json_array_size(entries);
    cap = count > MAX_ENTRIES ? MAX_ENTRIES : count;
    vault->entries = (otp_entry_t *)calloc(cap > 0 ? cap : 1, sizeof(otp_entry_t));
    if (vault->entries == NULL)
    {
        i_set_error(err, errlen, "Out of memory.");
        return -1;
    }
    vault->count = 0;
    vault->skipped = 0;

    for (i = 0; i < count; i += 1)
    {
        const Json *obj = json_array_get(entries, i);
        const Json *info;
        const char *type;
        const char *algo;
        const char *secret_text;
        const char *issuer;
        const char *name;
        otp_entry_t entry;
        unsigned char secret[512];
        size_t secret_len = 0;
        long long digits;
        long long period;
        long long counter;

        if (vault->count >= MAX_ENTRIES)
        {
            vault->skipped += count - i;
            break;
        }

        memset(&entry, 0, sizeof(entry));

        if (json_type(obj) != JSON_OBJECT)
        {
            vault->skipped += 1;
            continue;
        }

        type = json_string(json_object_get(obj, "type"));
        if (type == NULL)
        {
            vault->skipped += 1;
            continue;
        }

        if (strcasecmp(type, "totp") == 0)
            entry.kind = OTP_TOTP;
        else if (strcasecmp(type, "hotp") == 0)
            entry.kind = OTP_HOTP;
        else if (strcasecmp(type, "steam") == 0)
            entry.kind = OTP_STEAM;
        else
        {
            vault->skipped += 1;
            continue;
        }

        info = json_object_get(obj, "info");
        if (json_type(info) != JSON_OBJECT)
        {
            vault->skipped += 1;
            continue;
        }

        secret_text = json_string(json_object_get(info, "secret"));
        if (secret_text == NULL ||
            base32_decode(secret_text, secret, sizeof(secret), &secret_len) != 0 ||
            secret_len == 0)
        {
            vault->skipped += 1;
            continue;
        }

        if (i_algo_name(json_string(json_object_get(info, "algo")), entry.algo) != 0)
        {
            secure_wipe(secret, sizeof(secret));
            vault->skipped += 1;
            continue;
        }

        digits = json_integer(json_object_get(info, "digits"), 6);
        if (entry.kind == OTP_STEAM)
        {
            /* Steam codes are always five characters; the digits field is not
             * relevant to the algorithm. */
            entry.digits = 5;
        }
        else
        {
            if (digits < 4 || digits > 10)
            {
                secure_wipe(secret, sizeof(secret));
                vault->skipped += 1;
                continue;
            }
            entry.digits = (int)digits;
        }

        if (entry.kind == OTP_HOTP)
        {
            counter = json_integer(json_object_get(info, "counter"), 0);
            entry.counter = counter < 0 ? 0ull : (unsigned long long)counter;
            entry.period = 30;
        }
        else
        {
            period = json_integer(json_object_get(info, "period"), 30);
            if (period < 1 || period > 300)
            {
                secure_wipe(secret, sizeof(secret));
                vault->skipped += 1;
                continue;
            }
            entry.period = (int)period;
            entry.counter = 0;
        }

        issuer = json_string(json_object_get(obj, "issuer"));
        name = json_string(json_object_get(obj, "name"));
        entry.issuer = i_dup_string(issuer);
        entry.name = i_dup_string(name);
        entry.secret = (unsigned char *)malloc(secret_len);
        if (entry.issuer == NULL || entry.name == NULL || entry.secret == NULL)
        {
            free(entry.issuer);
            free(entry.name);
            free(entry.secret);
            secure_wipe(secret, sizeof(secret));
            i_set_error(err, errlen, "Out of memory.");
            return -1;
        }

        memcpy(entry.secret, secret, secret_len);
        entry.secret_len = secret_len;
        secure_wipe(secret, sizeof(secret));
        vault->entries[vault->count++] = entry;
    }

    return 0;
}

/*---------------------------------------------------------------------------*/

static int i_gcm_decrypt(const unsigned char *key, const unsigned char *nonce, size_t nonce_len,
                         const unsigned char *ciphertext, size_t ciphertext_len,
                         const unsigned char *tag, size_t tag_len,
                         unsigned char *out)
{
    EVP_CIPHER_CTX *ctx = NULL;
    int len = 0;
    int ok = 0;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        return -1;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        goto cleanup;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)nonce_len, NULL) != 1)
        goto cleanup;

    if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
        goto cleanup;

    if (ciphertext_len > 0)
    {
        if (EVP_DecryptUpdate(ctx, out, &len, ciphertext, (int)ciphertext_len) != 1)
            goto cleanup;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, (int)tag_len, (void *)tag) != 1)
        goto cleanup;

    if (EVP_DecryptFinal_ex(ctx, out + ciphertext_len, &len) != 1)
        goto cleanup;

    ok = 1;

cleanup:
    EVP_CIPHER_CTX_free(ctx);
    return ok ? 0 : -1;
}

/*---------------------------------------------------------------------------*/

static int i_decrypt(const Json *root, const char *password, vault_t *vault,
                     char *err, size_t errlen)
{
    const Json *header;
    const Json *slots;
    const Json *slot = NULL;
    const Json *key_params;
    const Json *params;
    const char *db_b64;
    const char *salt_hex;
    const char *key_hex;
    const char *key_nonce_hex;
    const char *key_tag_hex;
    const char *nonce_hex;
    const char *tag_hex;
    long long n;
    long long r;
    long long p;
    unsigned char salt[SALT_SIZE];
    unsigned char enc_key[KEY_SIZE];
    unsigned char key_nonce[GCM_NONCE_SIZE];
    unsigned char key_tag[GCM_TAG_SIZE];
    unsigned char nonce[GCM_NONCE_SIZE];
    unsigned char tag[GCM_TAG_SIZE];
    unsigned char derived[KEY_SIZE];
    unsigned char master[KEY_SIZE];
    unsigned char *ciphertext = NULL;
    size_t ciphertext_len = 0;
    char *plaintext = NULL;
    Json *decrypted = NULL;
    uint64_t maxmem;
    size_t i;
    int rc = VAULT_ERROR;

    memset(salt, 0, sizeof(salt));
    memset(enc_key, 0, sizeof(enc_key));
    memset(key_nonce, 0, sizeof(key_nonce));
    memset(key_tag, 0, sizeof(key_tag));
    memset(nonce, 0, sizeof(nonce));
    memset(tag, 0, sizeof(tag));
    memset(derived, 0, sizeof(derived));
    memset(master, 0, sizeof(master));

    header = json_object_get(root, "header");
    if (json_type(header) != JSON_OBJECT)
    {
        i_set_error(err, errlen, "Malformed Aegis backup: missing 'header' object.");
        goto cleanup;
    }

    slots = json_object_get(header, "slots");
    if (json_type(slots) != JSON_ARRAY)
    {
        i_set_error(err, errlen, "Malformed Aegis backup: missing 'slots' array.");
        goto cleanup;
    }

    for (i = 0; i < json_array_size(slots); i += 1)
    {
        const Json *candidate = json_array_get(slots, i);
        const Json *type = json_object_get(candidate, "type");
        if (json_integer(type, -1) == 1)
        {
            slot = candidate;
            break;
        }
    }

    if (slot == NULL)
    {
        i_set_error(err, errlen,
                    "No password slot found. This vault may only be unlockable with biometrics.");
        goto cleanup;
    }

    n = json_integer(json_object_get(slot, "n"), -1);
    r = json_integer(json_object_get(slot, "r"), 8);
    p = json_integer(json_object_get(slot, "p"), -1);

    if (n < 1024 || n > 131072 || (n & (n - 1)) != 0 ||
        r < 1 || r > 16 || p < 1 || p > 16 ||
        (uint64_t)n * (uint64_t)p > 1048576ull ||
        (uint64_t)128 * (uint64_t)n * (uint64_t)r > 256ull * 1024ull * 1024ull)
    {
        i_set_error(err, errlen, "Malformed Aegis backup: unsupported scrypt parameters.");
        goto cleanup;
    }

    salt_hex = json_string(json_object_get(slot, "salt"));
    key_hex = json_string(json_object_get(slot, "key"));

    key_params = json_object_get(slot, "key_params");
    key_nonce_hex = json_string(json_object_get(key_params, "nonce"));
    key_tag_hex = json_string(json_object_get(key_params, "tag"));

    params = json_object_get(header, "params");
    nonce_hex = json_string(json_object_get(params, "nonce"));
    tag_hex = json_string(json_object_get(params, "tag"));

    db_b64 = json_string(json_object_get(root, "db"));

    if (hex_decode_exact(salt_hex, salt, sizeof(salt)) != 0 ||
        hex_decode_exact(key_hex, enc_key, sizeof(enc_key)) != 0 ||
        hex_decode_exact(key_nonce_hex, key_nonce, sizeof(key_nonce)) != 0 ||
        hex_decode_exact(key_tag_hex, key_tag, sizeof(key_tag)) != 0)
    {
        i_set_error(err, errlen, "Malformed Aegis backup: invalid key slot fields.");
        goto cleanup;
    }

    if (hex_decode_exact(nonce_hex, nonce, sizeof(nonce)) != 0 ||
        hex_decode_exact(tag_hex, tag, sizeof(tag)) != 0)
    {
        i_set_error(err, errlen, "Malformed Aegis backup: invalid database parameters.");
        goto cleanup;
    }

    if (db_b64 == NULL || base64_decode(db_b64, &ciphertext, &ciphertext_len) != 0 ||
        ciphertext_len == 0)
    {
        i_set_error(err, errlen, "Malformed Aegis backup: missing or invalid 'db' field.");
        goto cleanup;
    }

    maxmem = 128ull * (uint64_t)n * (uint64_t)r + (1ull << 20);
    if (EVP_PBE_scrypt(password, strlen(password), salt, sizeof(salt),
                       (uint64_t)n, (uint64_t)r, (uint64_t)p,
                       maxmem, derived, sizeof(derived)) != 1)
    {
        i_set_error(err, errlen, "Could not derive the vault key (scrypt failed).");
        goto cleanup;
    }

    if (i_gcm_decrypt(derived, key_nonce, sizeof(key_nonce), enc_key, sizeof(enc_key),
                      key_tag, sizeof(key_tag), master) != 0)
    {
        i_set_error(err, errlen, "Wrong password, or the vault is corrupted.");
        rc = VAULT_BAD_PASSWORD;
        goto cleanup;
    }

    plaintext = (char *)malloc(ciphertext_len + 1);
    if (plaintext == NULL)
    {
        i_set_error(err, errlen, "Out of memory.");
        goto cleanup;
    }

    if (i_gcm_decrypt(master, nonce, sizeof(nonce), ciphertext, ciphertext_len,
                      tag, sizeof(tag), (unsigned char *)plaintext) != 0)
    {
        i_set_error(err, errlen, "Wrong password, or the vault is corrupted.");
        rc = VAULT_BAD_PASSWORD;
        goto cleanup;
    }
    plaintext[ciphertext_len] = '\0';

    decrypted = json_parse(plaintext, ciphertext_len, err, errlen);
    if (decrypted == NULL)
    {
        if (err != NULL && errlen > 0 && err[0] == '\0')
            i_set_error(err, errlen, "The decrypted vault is not valid JSON.");
        goto cleanup;
    }

    if (i_parse_entries(decrypted, vault, err, errlen) != 0)
        goto cleanup;

    rc = VAULT_OK;

cleanup:
    if (plaintext != NULL)
    {
        secure_wipe(plaintext, ciphertext_len);
        free(plaintext);
    }
    if (ciphertext != NULL)
    {
        secure_wipe(ciphertext, ciphertext_len);
        free(ciphertext);
    }
    if (decrypted != NULL)
        json_free(decrypted);
    secure_wipe(enc_key, sizeof(enc_key));
    secure_wipe(derived, sizeof(derived));
    secure_wipe(master, sizeof(master));
    return rc;
}

/*---------------------------------------------------------------------------*/

int vault_load(const char *path, const char *password, vault_t *vault,
               char *err, size_t errlen)
{
    vault_t result;
    char *text = NULL;
    size_t textlen = 0;
    Json *root = NULL;
    const Json *db;
    int rc = VAULT_ERROR;

    memset(&result, 0, sizeof(result));
    if (err != NULL && errlen > 0)
        err[0] = '\0';

    if (path == NULL)
    {
        i_set_error(err, errlen, "No file selected.");
        return VAULT_ERROR;
    }

    if (i_read_file(path, &text, &textlen, err, errlen) != 0)
        return VAULT_ERROR;

    {
        const char *start = text;
        while (*start == ' ' || *start == '\t' || *start == '\r' || *start == '\n')
            start += 1;

        if (*start != '{')
        {
            if (strstr(start, "otpauth://") != NULL)
                i_set_error(err, errlen,
                            "This is an otpauth:// text export. In Aegis choose Export and pick the JSON format.");
            else
                i_set_error(err, errlen, "This is not an Aegis JSON export.");
            secure_wipe(text, textlen);
            free(text);
            return VAULT_ERROR;
        }
    }

    root = json_parse(text, textlen, err, errlen);
    secure_wipe(text, textlen);
    free(text);
    if (root == NULL)
        return VAULT_ERROR;

    db = json_object_get(root, "db");
    if (json_type(db) == JSON_OBJECT)
    {
        if (i_parse_entries(db, &result, err, errlen) == 0)
            rc = VAULT_OK;
    }
    else if (json_type(db) == JSON_STRING)
    {
        if (password == NULL)
        {
            i_set_error(err, errlen, "This vault is encrypted.");
            rc = VAULT_NEED_PASSWORD;
        }
        else
        {
            rc = i_decrypt(root, password, &result, err, errlen);
        }
    }
    else
    {
        i_set_error(err, errlen, "This is not an Aegis export (missing 'db' object).");
    }

    json_free(root);

    if (rc == VAULT_OK)
        *vault = result;
    else
        vault_free(&result);

    return rc;
}

/*---------------------------------------------------------------------------*/

void vault_free(vault_t *vault)
{
    size_t i;

    if (vault == NULL)
        return;

    for (i = 0; i < vault->count; i += 1)
    {
        otp_entry_t *entry = &vault->entries[i];
        free(entry->issuer);
        free(entry->name);
        if (entry->secret != NULL)
        {
            secure_wipe(entry->secret, entry->secret_len);
            free(entry->secret);
        }
    }

    free(vault->entries);
    memset(vault, 0, sizeof(*vault));
}
