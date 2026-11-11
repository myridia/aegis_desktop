/*
 * Minimal JSON parser for reading Aegis Authenticator exports.
 * Read-only DOM. Strings are UTF-8 (escapes decoded).
 */

#ifndef AEGIS_JSON_H
#define AEGIS_JSON_H

#include <stddef.h>

typedef enum
{
    JSON_NULL = 0,
    JSON_BOOL,
    JSON_NUMBER,
    JSON_STRING,
    JSON_ARRAY,
    JSON_OBJECT
} JsonType;

typedef struct Json Json;

/* Returns NULL on malformed input or out of memory. */
Json *json_parse(const char *text, size_t len, char *err, size_t errlen);
void json_free(Json *json);

JsonType json_type(const Json *json);

/* Object lookup. Returns NULL if 'object' is not an object or key is absent. */
const Json *json_object_get(const Json *object, const char *key);

/* Array access. Returns NULL if out of range. */
const Json *json_array_get(const Json *array, size_t index);
size_t json_array_size(const Json *array);

const char *json_string(const Json *json);
double json_number(const Json *json, double def);
long long json_integer(const Json *json, long long def);
int json_boolean(const Json *json, int def);

#endif
