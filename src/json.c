#include "json.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

struct Json
{
    JsonType type;
    union
    {
        int boolean;
        double number;
        char *string;
        struct
        {
            Json **items;
            size_t count;
            size_t cap;
        } array;
        struct
        {
            char **keys;
            Json **values;
            size_t count;
            size_t cap;
        } object;
    } u;
};

typedef struct
{
    const char *s;
    size_t len;
    size_t pos;
    int depth;
    int failed;
    char *err;
    size_t errlen;
} Parser;

/*---------------------------------------------------------------------------*/

static void i_wipe(void *ptr, size_t size)
{
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (size-- > 0)
        *p++ = 0;
}

/*---------------------------------------------------------------------------*/

static void i_error(Parser *p, const char *message)
{
    if (p->failed == 0)
    {
        p->failed = 1;
        if (p->err != NULL && p->errlen > 0)
            snprintf(p->err, p->errlen, "%s at byte %lu", message, (unsigned long)p->pos);
    }
}

/*---------------------------------------------------------------------------*/

static void i_skip_ws(Parser *p)
{
    while (p->pos < p->len)
    {
        char c = p->s[p->pos];
        if (c == ' ' || c == '\t' || c == '\r' || c == '\n')
            p->pos += 1;
        else
            break;
    }
}

/*---------------------------------------------------------------------------*/

static Json *i_new(Parser *p, const JsonType type)
{
    Json *json = (Json *)calloc(1, sizeof(Json));
    if (json == NULL)
    {
        i_error(p, "out of memory");
        return NULL;
    }
    json->type = type;
    return json;
}

/*---------------------------------------------------------------------------*/

static int i_hex4(Parser *p, unsigned int *value)
{
    unsigned int result = 0;
    int i;
    if (p->pos + 4 > p->len)
        return -1;

    for (i = 0; i < 4; i += 1)
    {
        char c = p->s[p->pos + (size_t)i];
        unsigned int v;
        if (c >= '0' && c <= '9')
            v = (unsigned int)(c - '0');
        else if (c >= 'a' && c <= 'f')
            v = (unsigned int)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F')
            v = (unsigned int)(c - 'A' + 10);
        else
            return -1;
        result = (result << 4) | v;
    }

    p->pos += 4;
    *value = result;
    return 0;
}

/*---------------------------------------------------------------------------*/

static size_t i_utf8(unsigned int cp, char *out)
{
    if (cp <= 0x7F)
    {
        out[0] = (char)cp;
        return 1;
    }
    else if (cp <= 0x7FF)
    {
        out[0] = (char)(0xC0 | (cp >> 6));
        out[1] = (char)(0x80 | (cp & 0x3F));
        return 2;
    }
    else if (cp <= 0xFFFF)
    {
        out[0] = (char)(0xE0 | (cp >> 12));
        out[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
        out[2] = (char)(0x80 | (cp & 0x3F));
        return 3;
    }
    else
    {
        out[0] = (char)(0xF0 | (cp >> 18));
        out[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
        out[2] = (char)(0x80 | ((cp >> 6) & 0x3F));
        out[3] = (char)(0x80 | (cp & 0x3F));
        return 4;
    }
}

/*---------------------------------------------------------------------------*/

static char *i_parse_string(Parser *p)
{
    size_t start;
    size_t out;
    char *buf;

    if (p->pos >= p->len || p->s[p->pos] != '"')
    {
        i_error(p, "expected string");
        return NULL;
    }

    p->pos += 1;
    start = p->pos;
    buf = (char *)malloc(p->len - start + 1);
    if (buf == NULL)
    {
        i_error(p, "out of memory");
        return NULL;
    }
    out = 0;

    while (p->pos < p->len)
    {
        unsigned char c = (unsigned char)p->s[p->pos];

        if (c == '"')
        {
            p->pos += 1;
            buf[out] = '\0';
            return buf;
        }
        else if (c == '\\')
        {
            p->pos += 1;
            if (p->pos >= p->len)
            {
                i_error(p, "unterminated escape");
                break;
            }

            switch (p->s[p->pos])
            {
            case '"':
                buf[out++] = '"';
                p->pos += 1;
                break;
            case '\\':
                buf[out++] = '\\';
                p->pos += 1;
                break;
            case '/':
                buf[out++] = '/';
                p->pos += 1;
                break;
            case 'b':
                buf[out++] = '\b';
                p->pos += 1;
                break;
            case 'f':
                buf[out++] = '\f';
                p->pos += 1;
                break;
            case 'n':
                buf[out++] = '\n';
                p->pos += 1;
                break;
            case 'r':
                buf[out++] = '\r';
                p->pos += 1;
                break;
            case 't':
                buf[out++] = '\t';
                p->pos += 1;
                break;
            case 'u':
            {
                unsigned int cp = 0xFFFD;
                p->pos += 1;
                if (i_hex4(p, &cp) != 0)
                {
                    i_error(p, "invalid unicode escape");
                    break;
                }

                if (cp >= 0xD800 && cp <= 0xDBFF)
                {
                    /* Try to read a UTF-16 surrogate pair. */
                    if (p->pos + 6 <= p->len && p->s[p->pos] == '\\' && p->s[p->pos + 1] == 'u')
                    {
                        size_t save = p->pos;
                        unsigned int low = 0;
                        p->pos += 2;
                        if (i_hex4(p, &low) == 0 && low >= 0xDC00 && low <= 0xDFFF)
                            cp = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00);
                        else
                        {
                            p->pos = save;
                            cp = 0xFFFD;
                        }
                    }
                    else
                    {
                        cp = 0xFFFD;
                    }
                }
                else if (cp >= 0xDC00 && cp <= 0xDFFF)
                {
                    cp = 0xFFFD;
                }

                out += i_utf8(cp, buf + out);
                break;
            }
            default:
                i_error(p, "invalid escape");
                break;
            }

            if (p->failed)
                break;
        }
        else if (c < 0x20)
        {
            i_error(p, "control character in string");
            break;
        }
        else
        {
            buf[out++] = (char)c;
            p->pos += 1;
        }
    }

    if (p->failed == 0)
        i_error(p, "unterminated string");
    i_wipe(buf, out);
    free(buf);
    return NULL;
}

/*---------------------------------------------------------------------------*/

static int i_is_digit(const char c)
{
    return c >= '0' && c <= '9';
}

/*---------------------------------------------------------------------------*/

static Json *i_parse_number(Parser *p)
{
    size_t start = p->pos;
    size_t numlen;
    char stackbuf[64];
    char *tmp = stackbuf;
    char *end = NULL;
    Json *json;

    if (p->pos < p->len && p->s[p->pos] == '-')
        p->pos += 1;

    if (p->pos >= p->len)
    {
        i_error(p, "invalid number");
        return NULL;
    }

    if (p->s[p->pos] == '0')
    {
        p->pos += 1;
    }
    else if (p->s[p->pos] >= '1' && p->s[p->pos] <= '9')
    {
        while (p->pos < p->len && i_is_digit(p->s[p->pos]))
            p->pos += 1;
    }
    else
    {
        i_error(p, "invalid number");
        return NULL;
    }

    if (p->pos < p->len && p->s[p->pos] == '.')
    {
        p->pos += 1;
        if (p->pos >= p->len || !i_is_digit(p->s[p->pos]))
        {
            i_error(p, "invalid number fraction");
            return NULL;
        }
        while (p->pos < p->len && i_is_digit(p->s[p->pos]))
            p->pos += 1;
    }

    if (p->pos < p->len && (p->s[p->pos] == 'e' || p->s[p->pos] == 'E'))
    {
        p->pos += 1;
        if (p->pos < p->len && (p->s[p->pos] == '+' || p->s[p->pos] == '-'))
            p->pos += 1;
        if (p->pos >= p->len || !i_is_digit(p->s[p->pos]))
        {
            i_error(p, "invalid number exponent");
            return NULL;
        }
        while (p->pos < p->len && i_is_digit(p->s[p->pos]))
            p->pos += 1;
    }

    numlen = p->pos - start;
    if (numlen + 1 > sizeof(stackbuf))
    {
        tmp = (char *)malloc(numlen + 1);
        if (tmp == NULL)
        {
            i_error(p, "out of memory");
            return NULL;
        }
    }
    memcpy(tmp, p->s + start, numlen);
    tmp[numlen] = '\0';
    json = i_new(p, JSON_NUMBER);
    if (json != NULL)
    {
        double value = strtod(tmp, &end);
        if (end == NULL || *end != '\0')
        {
            i_error(p, "invalid number");
            json_free(json);
            json = NULL;
        }
        else
        {
            json->u.number = value;
        }
    }
    if (tmp != stackbuf)
        free(tmp);
    return json;
}

/*---------------------------------------------------------------------------*/

static Json *i_parse_value(Parser *p);

/*---------------------------------------------------------------------------*/

static int i_array_append(Parser *p, Json *array, Json *item)
{
    if (array->u.array.count == array->u.array.cap)
    {
        size_t cap = array->u.array.cap == 0 ? 8 : array->u.array.cap * 2;
        Json **items = (Json **)realloc(array->u.array.items, cap * sizeof(Json *));
        if (items == NULL)
        {
            i_error(p, "out of memory");
            return -1;
        }
        array->u.array.items = items;
        array->u.array.cap = cap;
    }
    array->u.array.items[array->u.array.count++] = item;
    return 0;
}

/*---------------------------------------------------------------------------*/

static int i_object_append(Parser *p, Json *object, char *key, Json *value)
{
    if (object->u.object.count == object->u.object.cap)
    {
        size_t cap = object->u.object.cap == 0 ? 8 : object->u.object.cap * 2;
        char **keys = (char **)realloc(object->u.object.keys, cap * sizeof(char *));
        Json **values = (Json **)realloc(object->u.object.values, cap * sizeof(Json *));
        if (keys == NULL || values == NULL)
        {
            if (keys != NULL)
                object->u.object.keys = keys;
            if (values != NULL)
                object->u.object.values = values;
            i_error(p, "out of memory");
            return -1;
        }
        object->u.object.keys = keys;
        object->u.object.values = values;
        object->u.object.cap = cap;
    }
    object->u.object.keys[object->u.object.count] = key;
    object->u.object.values[object->u.object.count] = value;
    object->u.object.count += 1;
    return 0;
}

/*---------------------------------------------------------------------------*/

static Json *i_parse_array(Parser *p)
{
    Json *array = i_new(p, JSON_ARRAY);
    if (array == NULL)
        return NULL;

    p->pos += 1; /* '[' */
    i_skip_ws(p);

    if (p->pos < p->len && p->s[p->pos] == ']')
    {
        p->pos += 1;
        return array;
    }

    while (p->failed == 0)
    {
        Json *item = i_parse_value(p);
        if (item == NULL)
            break;
        if (i_array_append(p, array, item) != 0)
        {
            json_free(item);
            break;
        }

        i_skip_ws(p);
        if (p->pos >= p->len)
        {
            i_error(p, "unterminated array");
            break;
        }
        if (p->s[p->pos] == ',')
        {
            p->pos += 1;
            i_skip_ws(p);
            continue;
        }
        if (p->s[p->pos] == ']')
        {
            p->pos += 1;
            return array;
        }

        i_error(p, "expected ',' or ']'");
        break;
    }

    json_free(array);
    return NULL;
}

/*---------------------------------------------------------------------------*/

static Json *i_parse_object(Parser *p)
{
    Json *object = i_new(p, JSON_OBJECT);
    if (object == NULL)
        return NULL;

    p->pos += 1; /* '{' */
    i_skip_ws(p);

    if (p->pos < p->len && p->s[p->pos] == '}')
    {
        p->pos += 1;
        return object;
    }

    while (p->failed == 0)
    {
        char *key = i_parse_string(p);
        Json *value;

        if (key == NULL)
            break;

        i_skip_ws(p);
        if (p->pos >= p->len || p->s[p->pos] != ':')
        {
            i_error(p, "expected ':'");
            i_wipe(key, strlen(key));
            free(key);
            break;
        }
        p->pos += 1;

        value = i_parse_value(p);
        if (value == NULL)
        {
            i_wipe(key, strlen(key));
            free(key);
            break;
        }

        if (i_object_append(p, object, key, value) != 0)
        {
            i_wipe(key, strlen(key));
            free(key);
            json_free(value);
            break;
        }

        i_skip_ws(p);
        if (p->pos >= p->len)
        {
            i_error(p, "unterminated object");
            break;
        }
        if (p->s[p->pos] == ',')
        {
            p->pos += 1;
            i_skip_ws(p);
            continue;
        }
        if (p->s[p->pos] == '}')
        {
            p->pos += 1;
            return object;
        }

        i_error(p, "expected ',' or '}'");
        break;
    }

    json_free(object);
    return NULL;
}

/*---------------------------------------------------------------------------*/

static Json *i_parse_value(Parser *p)
{
    char c;

    i_skip_ws(p);
    if (p->pos >= p->len)
    {
        i_error(p, "unexpected end of input");
        return NULL;
    }

    if (p->depth >= 64)
    {
        i_error(p, "nesting too deep");
        return NULL;
    }
    p->depth += 1;

    c = p->s[p->pos];
    if (c == '{')
    {
        Json *json = i_parse_object(p);
        p->depth -= 1;
        return json;
    }
    else if (c == '[')
    {
        Json *json = i_parse_array(p);
        p->depth -= 1;
        return json;
    }
    else if (c == '"')
    {
        Json *json = i_new(p, JSON_STRING);
        p->depth -= 1;
        if (json == NULL)
            return NULL;
        json->u.string = i_parse_string(p);
        if (json->u.string == NULL)
        {
            free(json);
            return NULL;
        }
        return json;
    }
    else if (c == 't' && p->pos + 4 <= p->len && strncmp(p->s + p->pos, "true", 4) == 0)
    {
        Json *json = i_new(p, JSON_BOOL);
        p->pos += 4;
        p->depth -= 1;
        if (json != NULL)
            json->u.boolean = 1;
        return json;
    }
    else if (c == 'f' && p->pos + 5 <= p->len && strncmp(p->s + p->pos, "false", 5) == 0)
    {
        Json *json = i_new(p, JSON_BOOL);
        p->pos += 5;
        p->depth -= 1;
        if (json != NULL)
            json->u.boolean = 0;
        return json;
    }
    else if (c == 'n' && p->pos + 4 <= p->len && strncmp(p->s + p->pos, "null", 4) == 0)
    {
        Json *json = i_new(p, JSON_NULL);
        p->pos += 4;
        p->depth -= 1;
        return json;
    }
    else if (c == '-' || (c >= '0' && c <= '9'))
    {
        Json *json = i_parse_number(p);
        p->depth -= 1;
        return json;
    }

    i_error(p, "unexpected character");
    p->depth -= 1;
    return NULL;
}

/*---------------------------------------------------------------------------*/

Json *json_parse(const char *text, size_t len, char *err, size_t errlen)
{
    Parser p;
    Json *root;

    memset(&p, 0, sizeof(p));
    p.s = text;
    p.len = len;
    p.err = err;
    p.errlen = errlen;
    if (err != NULL && errlen > 0)
        err[0] = '\0';

    /* Skip UTF-8 BOM if present. */
    if (len >= 3 && (unsigned char)text[0] == 0xEF && (unsigned char)text[1] == 0xBB && (unsigned char)text[2] == 0xBF)
        p.pos = 3;

    root = i_parse_value(&p);
    if (root == NULL)
        return NULL;

    i_skip_ws(&p);
    if (p.pos != p.len)
    {
        i_error(&p, "trailing data");
        json_free(root);
        return NULL;
    }

    return root;
}

/*---------------------------------------------------------------------------*/

void json_free(Json *json)
{
    size_t i;

    if (json == NULL)
        return;

    switch (json->type)
    {
    case JSON_STRING:
        if (json->u.string != NULL)
        {
            i_wipe(json->u.string, strlen(json->u.string));
            free(json->u.string);
        }
        break;

    case JSON_ARRAY:
        for (i = 0; i < json->u.array.count; i += 1)
            json_free(json->u.array.items[i]);
        free(json->u.array.items);
        break;

    case JSON_OBJECT:
        for (i = 0; i < json->u.object.count; i += 1)
        {
            Json *value = json->u.object.values[i];
            char *key = json->u.object.keys[i];
            json_free(value);
            if (key != NULL)
            {
                i_wipe(key, strlen(key));
                free(key);
            }
        }
        free(json->u.object.keys);
        free(json->u.object.values);
        break;

    default:
        break;
    }

    free(json);
}

/*---------------------------------------------------------------------------*/

JsonType json_type(const Json *json)
{
    return json != NULL ? json->type : JSON_NULL;
}

/*---------------------------------------------------------------------------*/

const Json *json_object_get(const Json *object, const char *key)
{
    size_t i;
    const Json *found = NULL;

    if (object == NULL || object->type != JSON_OBJECT || key == NULL)
        return NULL;

    for (i = 0; i < object->u.object.count; i += 1)
    {
        if (strcmp(object->u.object.keys[i], key) == 0)
            found = object->u.object.values[i];
    }
    return found;
}

/*---------------------------------------------------------------------------*/

const Json *json_array_get(const Json *array, size_t index)
{
    if (array == NULL || array->type != JSON_ARRAY || index >= array->u.array.count)
        return NULL;
    return array->u.array.items[index];
}

/*---------------------------------------------------------------------------*/

size_t json_array_size(const Json *array)
{
    if (array == NULL || array->type != JSON_ARRAY)
        return 0;
    return array->u.array.count;
}

/*---------------------------------------------------------------------------*/

const char *json_string(const Json *json)
{
    if (json == NULL || json->type != JSON_STRING)
        return NULL;
    return json->u.string;
}

/*---------------------------------------------------------------------------*/

double json_number(const Json *json, double def)
{
    if (json == NULL || json->type != JSON_NUMBER)
        return def;
    return json->u.number;
}

/*---------------------------------------------------------------------------*/

long long json_integer(const Json *json, long long def)
{
    if (json == NULL || json->type != JSON_NUMBER)
        return def;
    if (json->u.number > 9007199254740992.0 || json->u.number < -9007199254740992.0)
        return def;
    return (long long)json->u.number;
}

/*---------------------------------------------------------------------------*/

int json_boolean(const Json *json, int def)
{
    if (json == NULL || json->type != JSON_BOOL)
        return def;
    return json->u.boolean;
}
