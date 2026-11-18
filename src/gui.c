#include "gui.h"

#include <nappgui.h>
#include <sewer/bstd.h>

#include "clipboard.h"
#include "util.h"
#include "vault.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#if defined(_WIN32)
#include <windows.h>
#else
#include <sys/stat.h>
#include <sys/types.h>
#endif

#define PASSWORD_MAX 256
#define PATH_MAX_LEN 1024

struct _app_t
{
    Window *window;
    Panel *panel;
    TableView *table;
    Edit *filter;
    Label *status;
    vault_t vault;
    uint32_t *rows; /* indices into vault.entries currently displayed */
    uint32_t nrows;
    char search[128];
    char temp[512];
    char status_text[512];
    char password[PASSWORD_MAX];
    char path[PATH_MAX_LEN];
    time_t last_time;
    Font *mono;
    int encrypted;
};

typedef struct _prompt_t
{
    Window *window;
    Edit *edit;
    App *app;
    bool_t accepted;
} Prompt;

typedef struct _about_t
{
    Window *window;
} About;

/*---------------------------------------------------------------------------*/

static bool_t i_contains_ci(const char_t *haystack, const char_t *needle)
{
    size_t nlen;
    const char_t *h;
    cassert_no_null(haystack);
    cassert_no_null(needle);

    nlen = strlen(needle);
    if (nlen == 0)
        return TRUE;

    for (h = haystack; *h != '\0'; h += 1)
    {
        size_t i = 0;
        while (i < nlen && h[i] != '\0' &&
               tolower((unsigned char)h[i]) == tolower((unsigned char)needle[i]))
            i += 1;
        if (i == nlen)
            return TRUE;
    }

    return FALSE;
}

/*---------------------------------------------------------------------------*/

static const char_t *i_entry_label(const otp_entry_t *entry, char_t *buffer, const size_t size)
{
    const char_t *issuer = entry->issuer != NULL ? entry->issuer : "";
    const char_t *name = entry->name != NULL ? entry->name : "";

    if (issuer[0] != '\0' && name[0] != '\0')
        bstd_sprintf(buffer, (uint32_t)size, "%s - %s", issuer, name);
    else if (issuer[0] != '\0')
        bstd_sprintf(buffer, (uint32_t)size, "%s", issuer);
    else if (name[0] != '\0')
        bstd_sprintf(buffer, (uint32_t)size, "%s", name);
    else
        bstd_sprintf(buffer, (uint32_t)size, "(unnamed)");

    return buffer;
}

/*---------------------------------------------------------------------------*/

static bool_t i_entry_code(const otp_entry_t *entry, char_t *out, const size_t outlen,
                           int32_t *left, uint64_t *counter)
{
    time_t now = time(NULL);
    int32_t period = entry->period > 0 ? (int32_t)entry->period : 30;
    uint64_t moving;

    if (entry->kind == OTP_HOTP)
    {
        moving = (uint64_t)entry->counter;
        if (left != NULL)
            *left = -1;
    }
    else
    {
        moving = (uint64_t)now / (uint64_t)period;
        if (left != NULL)
            *left = period - (int32_t)((uint64_t)now % (uint64_t)period);
    }

    if (counter != NULL)
        *counter = moving;

    return otp_generate(entry->secret, entry->secret_len, entry->algo, entry->kind,
                        entry->digits, moving, out, outlen) == 0;
}

/*---------------------------------------------------------------------------*/

static void i_set_status(App *app, const char_t *text)
{
    cassert_no_null(app);
    bstd_sprintf(app->status_text, sizeof(app->status_text), "%s", text != NULL ? text : "");
    label_text(app->status, app->status_text);
}

/*---------------------------------------------------------------------------*/

static void i_rebuild_rows(App *app)
{
    uint32_t i;
    uint32_t count = 0;

    if (app->rows != NULL)
    {
        free(app->rows);
        app->rows = NULL;
    }
    app->nrows = 0;

    if (app->vault.count == 0)
        return;

    app->rows = (uint32_t *)malloc(app->vault.count * sizeof(uint32_t));
    if (app->rows == NULL)
    {
        i_set_status(app, "Out of memory while filtering the vault.");
        return;
    }

    for (i = 0; i < (uint32_t)app->vault.count; i += 1)
    {
        const otp_entry_t *entry = &app->vault.entries[i];
        const char_t *issuer = entry->issuer != NULL ? entry->issuer : "";
        const char_t *name = entry->name != NULL ? entry->name : "";
        if (app->search[0] == '\0' || i_contains_ci(issuer, app->search) || i_contains_ci(name, app->search))
            app->rows[count++] = i;
    }

    app->nrows = count;
}

/*---------------------------------------------------------------------------*/

static void i_refresh_table(App *app)
{
    if (app->table != NULL)
        tableview_update(app->table);
}

/*---------------------------------------------------------------------------*/

static void i_OnTableData(App *app, Event *e)
{
    cassert_no_null(app);

    switch (event_type(e))
    {
    case ekGUI_EVENT_TBL_NROWS:
        *event_result(e, uint32_t) = app->nrows;
        break;

    case ekGUI_EVENT_TBL_CELL:
    {
        const EvTbPos *pos = event_params(e, EvTbPos);
        EvTbCell *cell = event_result(e, EvTbCell);
        const otp_entry_t *entry;

        cell->align = ekLEFT;
        cell->text = "";

        if (pos->row >= app->nrows)
            break;

        entry = &app->vault.entries[app->rows[pos->row]];

        switch (pos->col)
        {
        case 0:
            cell->text = entry->issuer != NULL ? entry->issuer : "";
            break;

        case 1:
            cell->text = entry->name != NULL ? entry->name : "";
            break;

        case 2:
        {
            char_t code[32];
            if (i_entry_code(entry, code, sizeof(code), NULL, NULL) == TRUE)
                bstd_sprintf(app->temp, sizeof(app->temp), "%s", code);
            else
                bstd_sprintf(app->temp, sizeof(app->temp), "error");
            cell->align = ekCENTER;
            cell->text = app->temp;
            break;
        }

        case 3:
        {
            int32_t left = 0;
            if (entry->kind == OTP_HOTP)
            {
                cell->text = "next";
            }
            else
            {
                i_entry_code(entry, app->temp, sizeof(app->temp), &left, NULL);
                bstd_sprintf(app->temp, sizeof(app->temp), "%ds", left);
                cell->align = ekCENTER;
                cell->text = app->temp;
            }
            break;
        }

        default:
            break;
        }

        break;
    }

    default:
        break;
    }
}

/*---------------------------------------------------------------------------*/

static bool_t i_row_entry(App *app, const uint32_t row, otp_entry_t **entry)
{
    cassert_no_null(app);
    cassert_no_null(entry);

    if (row >= app->nrows)
        return FALSE;

    *entry = &app->vault.entries[app->rows[row]];
    return TRUE;
}

/*---------------------------------------------------------------------------*/

static void i_copy_row(App *app, const uint32_t row, const bool_t advance_hotp)
{
    otp_entry_t *entry = NULL;
    char_t code[32];
    char_t label[256];
    char_t message[512];

    if (i_row_entry(app, row, &entry) == FALSE)
        return;

    if (i_entry_code(entry, code, sizeof(code), NULL, NULL) == FALSE)
    {
        i_set_status(app, "Could not generate the code for this entry.");
        return;
    }

    clip_copy(code);

    bstd_sprintf(message, sizeof(message), "Copied %s  (%s)", code,
                 i_entry_label(entry, label, sizeof(label)));
    i_set_status(app, message);

    if (advance_hotp == TRUE && entry->kind == OTP_HOTP)
    {
        entry->counter += 1;
        tableview_update(app->table);
    }
}

/*---------------------------------------------------------------------------*/

static void i_OnRowClick(App *app, Event *e)
{
    const EvTbRow *p = event_params(e, EvTbRow);
    cassert_no_null(app);
    cassert_no_null(p);

    if (p->row < app->nrows)
        i_copy_row(app, p->row, TRUE);
}

/*---------------------------------------------------------------------------*/

static void i_OnPromptOk(Prompt *prompt, Event *e)
{
    const char_t *text;
    cassert_no_null(prompt);

    text = edit_get_text(prompt->edit);
    bstd_sprintf(prompt->app->password, sizeof(prompt->app->password), "%s", text != NULL ? text : "");
    prompt->accepted = TRUE;
    window_stop_modal(prompt->window, 1);
    unref(e);
}

/*---------------------------------------------------------------------------*/

static void i_OnPromptCancel(Prompt *prompt, Event *e)
{
    cassert_no_null(prompt);
    prompt->accepted = FALSE;
    window_stop_modal(prompt->window, 0);
    unref(e);
}

/*---------------------------------------------------------------------------*/

static bool_t i_prompt_password(App *app, const char_t *win_title, const char_t *message,
                                const char_t *ok_label, const char_t *error_message)
{
    Window *window = window_create(ekWINDOW_TITLE | ekWINDOW_CLOSE | ekWINDOW_ESC);
    Layout *layout = layout_create(1, 4);
    Layout *buttons = layout_create(3, 1);
    Label *label = label_create();
    Label *error = label_create();
    Edit *edit = edit_create();
    Button *ok = button_push();
    Button *cancel = button_push();
    Panel *panel = panel_create();
    Prompt prompt;

    prompt.window = window;
    prompt.edit = edit;
    prompt.app = app;
    prompt.accepted = FALSE;

    window_title(window, win_title);
    label_text(label, message);
    label_multiline(label, TRUE);
    label_text(error, error_message != NULL ? error_message : "");
    label_color(error, color_rgb(190, 40, 40));
    label_multiline(error, TRUE);

    edit_passmode(edit, TRUE);
    edit_width(edit, 340);

    button_text(ok, ok_label);
    button_text(cancel, "Cancel");
    button_OnClick(ok, listener(&prompt, i_OnPromptOk, Prompt));
    button_OnClick(cancel, listener(&prompt, i_OnPromptCancel, Prompt));

    layout_label(layout, label, 0, 0);
    layout_edit(layout, edit, 0, 1);
    layout_label(layout, error, 0, 2);
    layout_layout(layout, buttons, 0, 3);
    layout_button(buttons, ok, 1, 0);
    layout_button(buttons, cancel, 2, 0);
    layout_hexpand(buttons, 0);
    layout_hmargin(buttons, 1, 6);
    layout_vmargin(layout, 0, 8);
    layout_vmargin(layout, 1, 8);
    layout_vmargin(layout, 2, 8);
    layout_margin(layout, 12);
    layout_halign(buttons, 1, 0, ekRIGHT);

    panel_layout(panel, layout);
    window_panel(window, panel);
    window_defbutton(window, ok);
    window_focus(window, guicontrol(edit));

    window_modal(window, app->window);
    window_destroy(&window);

    if (prompt.accepted == FALSE)
        secure_wipe(app->password, sizeof(app->password));

    return prompt.accepted;
}

/*---------------------------------------------------------------------------*/

static bool_t i_config_path(char *out, const size_t size, const char_t *name)
{
    const char *base;
    char dir[1024];

#if defined(_WIN32)
    base = getenv("APPDATA");
    if (base == NULL || base[0] == '\0')
        base = getenv("USERPROFILE");
    if (base == NULL || base[0] == '\0')
        return FALSE;
    bstd_sprintf(dir, sizeof(dir), "%s\\Aegis Desktop", base);
    CreateDirectoryA(dir, NULL);
    bstd_sprintf(out, (uint32_t)size, "%s\\%s", dir, name);
#else
    const char *home = getenv("HOME");
    char parent[1024];
    if (home == NULL || home[0] == '\0')
        return FALSE;
    bstd_sprintf(parent, sizeof(parent), "%s/.config", home);
    mkdir(parent, 0700);
    bstd_sprintf(dir, sizeof(dir), "%s/.config/aegis_desktop", home);
    mkdir(dir, 0700);
    bstd_sprintf(out, (uint32_t)size, "%s/%s", dir, name);
#endif
    return TRUE;
}

static void i_save_last_path(const char_t *path)
{
    char file[1200];
    FILE *f;

    if (i_config_path(file, sizeof(file), "last_export") == FALSE)
        return;

    f = fopen(file, "wb");
    if (f == NULL)
        return;

    fwrite(path, 1, strlen(path), f);
    fclose(f);
#if !defined(_WIN32)
    chmod(file, 0600);
#endif
}

static bool_t i_read_last_path(char *out, const size_t size)
{
    char file[1200];
    FILE *f;
    size_t n;

    if (i_config_path(file, sizeof(file), "last_export") == FALSE)
        return FALSE;

    f = fopen(file, "rb");
    if (f == NULL)
        return FALSE;

    n = fread(out, 1, size - 1, f);
    fclose(f);
    while (n > 0 && (out[n - 1] == '\n' || out[n - 1] == '\r'))
        n -= 1;
    out[n] = '\0';
    return n > 0;
}

static bool_t i_backup(const char_t *path, char_t *backup, const size_t backup_size)
{
    char ts[32];
    time_t now = time(NULL);
    unsigned char buffer[65536];
    FILE *src;
    FILE *dst;
    size_t n;

    if (strftime(ts, sizeof(ts), "%Y%m%d-%H%M%S", localtime(&now)) == 0)
        return FALSE;

    bstd_sprintf(backup, (uint32_t)backup_size, "%s.bak-%s", path, ts);

    src = fopen(path, "rb");
    if (src == NULL)
        return FALSE;

    dst = fopen(backup, "wb");
    if (dst == NULL)
    {
        fclose(src);
        return FALSE;
    }

    while ((n = fread(buffer, 1, sizeof(buffer), src)) > 0)
    {
        if (fwrite(buffer, 1, n, dst) != n)
        {
            fclose(src);
            fclose(dst);
            remove(backup);
            return FALSE;
        }
    }

    fclose(src);
    fclose(dst);

#if !defined(_WIN32)
    chmod(backup, 0600);
#endif

    return TRUE;
}

static bool_t i_store_copy(const char_t *src, char_t *dst, const size_t dst_size)
{
    unsigned char buffer[65536];
    size_t n;
    FILE *s;
    FILE *d;

    if (i_config_path(dst, dst_size, "imported.json") == FALSE)
        return FALSE;

    if (strcmp(src, dst) == 0)
        return TRUE;

    s = fopen(src, "rb");
    if (s == NULL)
        return FALSE;

    d = fopen(dst, "wb");
    if (d == NULL)
    {
        fclose(s);
        return FALSE;
    }

    while ((n = fread(buffer, 1, sizeof(buffer), s)) > 0)
    {
        if (fwrite(buffer, 1, n, d) != n)
        {
            fclose(s);
            fclose(d);
            remove(dst);
            return FALSE;
        }
    }

    fclose(s);
    fclose(d);

#if !defined(_WIN32)
    chmod(dst, 0600);
#endif

    return TRUE;
}

static void i_load_vault(App *app, const char_t *path)
{
    char_t error[256];
    char_t work[PATH_MAX_LEN];
    int attempt;

    cassert_no_null(app);
    cassert_no_null(path);

    secure_wipe(app->password, sizeof(app->password));
    error[0] = '\0';

    if (i_store_copy(path, work, sizeof(work)) == FALSE)
    {
        i_set_status(app, "Could not copy the export into the app storage. Import cancelled.");
        return;
    }

    path = work;

    {
        vault_t vault;
        int rc;
        int encrypted = 0;
        memset(&vault, 0, sizeof(vault));

        rc = vault_load(path, NULL, &vault, error, sizeof(error), &encrypted);

        attempt = 0;
        while (rc != VAULT_OK && attempt < 3 &&
               (rc == VAULT_NEED_PASSWORD || rc == VAULT_BAD_PASSWORD))
        {
            char_t message[256];
            bstd_sprintf(message, sizeof(message), "%s",
                         rc == VAULT_BAD_PASSWORD ? "Wrong password. Try again." : "");
            if (i_prompt_password(app, "Aegis vault password",
                                  "This Aegis export is encrypted. Type the vault password:",
                                  "Unlock", message) == FALSE)
            {
                i_set_status(app, "Import cancelled.");
                secure_wipe(app->password, sizeof(app->password));
                return;
            }
            error[0] = '\0';
            rc = vault_load(path, app->password, &vault, error, sizeof(error), &encrypted);
            attempt += 1;
        }

        secure_wipe(app->password, sizeof(app->password));

        if (rc != VAULT_OK)
        {
            i_set_status(app, error[0] != '\0' ? error : "Could not import the Aegis export.");
            vault_free(&vault);
            return;
        }

        vault_free(&app->vault);
        app->vault = vault;
        app->encrypted = encrypted;
        bstd_sprintf(app->path, sizeof(app->path), "%s", path);
        i_save_last_path(path);
    }

    i_rebuild_rows(app);
    tableview_deselect_all(app->table);
    tableview_update(app->table);

    if (app->vault.skipped > 0)
    {
        char_t message[256];
        bstd_sprintf(message, sizeof(message), "%u codes loaded. %u unsupported entries skipped.",
                     (unsigned int)app->nrows, (unsigned int)app->vault.skipped);
        i_set_status(app, message);
    }
    else
    {
        char_t message[256];
        bstd_sprintf(message, sizeof(message), "%u codes loaded. Click a row to copy, Cmd+N advances HOTP.",
                     (unsigned int)app->nrows);
        i_set_status(app, message);
    }
}

/*---------------------------------------------------------------------------*/

static void i_open_dialog(App *app)
{
    const char_t *types[] = {"json"};
    const char_t *file = comwin_open_file(app->window, "Import Aegis export", types, 1, NULL, NULL);

    if (file != NULL)
    {
        char_t path[PATH_MAX_LEN];
        /* The dialog's returned string is autoreleased; copy it before the
         * unlock loop runs its own modal event loop. */
        bstd_sprintf(path, sizeof(path), "%s", file);
        i_load_vault(app, path);
    }
}

/*---------------------------------------------------------------------------*/

static void i_OnOpen(App *app, Event *e)
{
    i_open_dialog(app);
    unref(e);
}

/*---------------------------------------------------------------------------*/

static void i_OnFilterChange(App *app, Event *e)
{
    const char_t *text = edit_get_text(app->filter);
    cassert_no_null(app);

    bstd_sprintf(app->search, sizeof(app->search), "%s", text != NULL ? text : "");
    i_rebuild_rows(app);
    tableview_deselect_all(app->table);
    i_refresh_table(app);
    unref(e);
}

/*---------------------------------------------------------------------------*/

static void i_OnFilterHotkey(App *app, Event *e)
{
    window_focus(app->window, guicontrol(app->filter));
    unref(e);
}

/*---------------------------------------------------------------------------*/

static void i_OnCopy(App *app, Event *e)
{
    const ArrSt(uint32_t) *selected = tableview_selected(app->table);

    if (arrst_size(selected, uint32_t) > 0)
    {
        uint32_t row = *arrst_get_const(selected, 0, uint32_t);
        i_copy_row(app, row, FALSE);
    }
    else
    {
        i_set_status(app, "Select a row first (or click it directly to copy).");
    }

    unref(e);
}

/*---------------------------------------------------------------------------*/

static void i_OnNext(App *app, Event *e)
{
    const ArrSt(uint32_t) *selected = tableview_selected(app->table);
    otp_entry_t *entry = NULL;

    if (arrst_size(selected, uint32_t) > 0)
    {
        uint32_t row = *arrst_get_const(selected, 0, uint32_t);
        if (i_row_entry(app, row, &entry) == TRUE && entry->kind == OTP_HOTP)
        {
            i_copy_row(app, row, TRUE);
            unref(e);
            return;
        }
    }

    /* Fall back to the first HOTP entry in the current view. */
    {
        uint32_t i;
        for (i = 0; i < app->nrows; i += 1)
        {
            if (app->vault.entries[app->rows[i]].kind == OTP_HOTP)
            {
                i_copy_row(app, i, TRUE);
                unref(e);
                return;
            }
        }
    }

    i_set_status(app, "No HOTP entry is visible.");
    unref(e);
}

/*---------------------------------------------------------------------------*/

static void i_OnExport(App *app, Event *e)
{
    const char_t *types[] = {"json"};
    const char_t *file;
    char_t path[PATH_MAX_LEN];
    char_t first[PASSWORD_MAX];
    char_t error[256];
    char_t message[512];
    bool_t encrypt;

    if (app->vault.count == 0)
    {
        i_set_status(app, "Nothing to export — import an Aegis export first.");
        unref(e);
        return;
    }

    file = comwin_save_file(app->window, "Export Aegis backup", types, 1, NULL, NULL);

    if (file == NULL)
    {
        unref(e);
        return;
    }

    bstd_sprintf(path, sizeof(path), "%s", file);

    {
        size_t len = strlen(path);
        const char_t *p;
        bool_t has_ext = FALSE;

        for (p = path + len; p > path; p -= 1)
        {
            char_t c = p[-1];

            if (c == '.')
            {
                has_ext = TRUE;
                break;
            }

            if (c == '/' || c == '\\')
                break;
        }

        if (has_ext == FALSE && len + 6 <= sizeof(path))
            strcat(path, ".json");
    }

    if (i_prompt_password(app, "Export Aegis backup",
                          "Leave empty for an unencrypted export, or type a password to encrypt it:",
                          "Export", "") == FALSE)
    {
        i_set_status(app, "Export cancelled.");
        unref(e);
        return;
    }

    bstd_sprintf(first, sizeof(first), "%s", app->password);
    encrypt = first[0] != '\0';

    if (encrypt)
    {
        if (i_prompt_password(app, "Export Aegis backup",
                              "Confirm the export password:",
                              "Export", "") == FALSE)
        {
            secure_wipe(first, sizeof(first));
            i_set_status(app, "Export cancelled.");
            unref(e);
            return;
        }

        if (strcmp(app->password, first) != 0)
        {
            secure_wipe(first, sizeof(first));
            secure_wipe(app->password, sizeof(app->password));
            i_set_status(app, "Passwords do not match. Export cancelled.");
            unref(e);
            return;
        }
    }

    error[0] = '\0';

    if (vault_export(&app->vault, path, encrypt ? first : NULL, error, sizeof(error)) != VAULT_OK)
    {
        secure_wipe(first, sizeof(first));
        secure_wipe(app->password, sizeof(app->password));
        i_set_status(app, error[0] != '\0' ? error : "Export failed.");
        unref(e);
        return;
    }

    bstd_sprintf(message, sizeof(message), "Exported %u codes to %s (%s).",
                 (unsigned int)app->vault.count, path,
                 encrypt ? "encrypted" : "unencrypted");
    secure_wipe(first, sizeof(first));
    secure_wipe(app->password, sizeof(app->password));
    i_set_status(app, message);
    unref(e);
}

/*---------------------------------------------------------------------------*/

static void i_OnAboutClose(About *about, Event *e)
{
    cassert_no_null(about);
    window_stop_modal(about->window, 1);
    unref(e);
}

static void i_OnAbout(App *app, Event *e)
{
    Window *window = window_create(ekWINDOW_TITLE | ekWINDOW_CLOSE | ekWINDOW_ESC);
    Layout *layout = layout_create(1, 4);
    Layout *buttons = layout_create(2, 1);
    Label *title = label_create();
    Label *text = label_create();
    Button *ok = button_push();
    Panel *panel = panel_create();
    About about;

    about.window = window;

    window_title(window, "About Aegis Desktop");
    label_text(title, "Aegis Desktop");
    label_text(text, "Read-only viewer for Aegis Authenticator exports.\nShows TOTP, HOTP and Steam codes from Aegis JSON exports. Secrets never leave memory.");
    label_multiline(text, TRUE);

    button_text(ok, "Close");
    button_OnClick(ok, listener(&about, i_OnAboutClose, About));

    layout_label(layout, title, 0, 0);
    layout_label(layout, text, 0, 1);
    layout_layout(layout, buttons, 0, 2);
    layout_button(buttons, ok, 1, 0);
    layout_hexpand(buttons, 0);
    layout_halign(buttons, 1, 0, ekRIGHT);
    layout_vmargin(layout, 0, 6);
    layout_vmargin(layout, 1, 10);
    layout_margin(layout, 16);

    panel_layout(panel, layout);
    window_panel(window, panel);
    window_defbutton(window, ok);

    window_modal(window, app->window);
    window_destroy(&window);
    unref(e);
}

/*---------------------------------------------------------------------------*/

static void i_OnDelete(App *app, Event *e)
{
    const ArrSt(uint32_t) *selected = tableview_selected(app->table);

    if (arrst_size(selected, uint32_t) == 0)
    {
        i_set_status(app, "Select a row first.");
        unref(e);
        return;
    }
    {
        uint32_t row = *arrst_get_const(selected, 0, uint32_t);
        char_t save_password[PASSWORD_MAX];
        char_t error[256];
        char_t backup[PATH_MAX_LEN + 32];
        char_t exported[PATH_MAX_LEN];

        save_password[0] = '\0';

        if (app->encrypted != 0)
        {
            vault_t probe;
            memset(&probe, 0, sizeof(probe));

            if (i_prompt_password(app, "Aegis vault password",
                                  "This Aegis export is encrypted. Type the vault password:",
                                  "Unlock", "") == FALSE)
            {
                i_set_status(app, "Delete cancelled.");
                unref(e);
                return;
            }

            bstd_sprintf(save_password, sizeof(save_password), "%s", app->password);
            secure_wipe(app->password, sizeof(app->password));

            error[0] = '\0';
            if (vault_load(app->path, save_password, &probe, error, sizeof(error), NULL) != VAULT_OK)
            {
                secure_wipe(save_password, sizeof(save_password));
                i_set_status(app, error[0] != '\0' ? error : "Wrong password. Delete not saved.");
                unref(e);
                return;
            }

            vault_free(&probe);
        }

        {
            otp_entry_t *entry = NULL;
            char_t label[256];
            uint32_t idx;

            if (i_row_entry(app, row, &entry) != TRUE)
            {
                secure_wipe(save_password, sizeof(save_password));
                unref(e);
                return;
            }

            bstd_sprintf(label, sizeof(label), "%s",
                         i_entry_label(entry, app->temp, sizeof(app->temp)));
            idx = (uint32_t)(entry - app->vault.entries);

            free(entry->issuer);
            free(entry->name);
            if (entry->secret != NULL)
            {
                secure_wipe(entry->secret, entry->secret_len);
                free(entry->secret);
            }

            {
                uint32_t i;
                for (i = idx + 1; i < (uint32_t)app->vault.count; i += 1)
                    app->vault.entries[i - 1] = app->vault.entries[i];
            }

            app->vault.entries[app->vault.count - 1].issuer = NULL;
            app->vault.entries[app->vault.count - 1].name = NULL;
            app->vault.entries[app->vault.count - 1].secret = NULL;
            app->vault.count -= 1;

            i_rebuild_rows(app);
            tableview_deselect_all(app->table);

            if (app->nrows > 0)
            {
                uint32_t target = row;
                uint32_t rows[1];

                if (target >= app->nrows)
                    target = app->nrows - 1;

                rows[0] = target;
                tableview_select(app->table, rows, 1);
            }

            tableview_update(app->table);

            bstd_sprintf(exported, sizeof(exported), "%s", app->path);
            backup[0] = '\0';
            error[0] = '\0';

            if (i_backup(exported, backup, sizeof(backup)) == FALSE)
            {
                secure_wipe(save_password, sizeof(save_password));
                i_set_status(app, "Deleted in memory, but the backup failed — deletion not saved; re-import to restore.");
                unref(e);
                return;
            }

            if (vault_export(&app->vault, exported,
                             app->encrypted != 0 ? save_password : NULL,
                             error, sizeof(error)) != VAULT_OK)
            {
                secure_wipe(save_password, sizeof(save_password));
                i_set_status(app, error[0] != '\0' ? error : "Delete not saved to the file.");
                unref(e);
                return;
            }

            {
                char_t message[512];
                bstd_sprintf(message, sizeof(message),
                             "Deleted %s. File updated; backup kept: %s", label, backup);
                secure_wipe(save_password, sizeof(save_password));
                i_set_status(app, message);
            }
        }
    }

    unref(e);
}

/*---------------------------------------------------------------------------*/

static void i_OnClose(App *app, Event *e)
{
    unref(app);
    unref(e);
    osapp_finish();
}

/*---------------------------------------------------------------------------*/

App *aegis_create(void)
{
    App *app = heap_new0(App);
    Layout *layout = layout_create(1, 3);
    Layout *toolbar = layout_create(6, 1);
    Button *open = button_push();
    Button *next = button_push();
    Button *del = button_push();
    Label *filter_label = label_create();

    app->window = window_create(ekWINDOW_STDRES);
    app->panel = panel_create();
    app->table = tableview_create();
    app->filter = edit_create();
    app->status = label_create();
    app->mono = font_monospace(font_regular_size(), 0);
    app->last_time = time(NULL);

    window_title(app->window, "Aegis Desktop");
    window_origin(app->window, v2df(180, 140));
    window_OnClose(app->window, listener(app, i_OnClose, App));

    button_text(open, "Import...");
    button_width(open, 120);
    button_OnClick(open, listener(app, i_OnOpen, App));

    button_text(del, "Delete");
    button_width(del, 80);
    button_tooltip(del, "Remove the selected entry for good on this device (Del)");
    button_OnClick(del, listener(app, i_OnDelete, App));

    button_text(next, "Next HOTP");
    button_width(next, 110);
    button_tooltip(next, "Advance the HOTP counter and copy the new code (Cmd+N)");
    button_OnClick(next, listener(app, i_OnNext, App));

    label_text(filter_label, "Filter:");
    edit_phtext(app->filter, "Issuer or account");
    edit_width(app->filter, 220);
    edit_OnChange(app->filter, listener(app, i_OnFilterChange, App));

    tableview_OnData(app->table, listener(app, i_OnTableData, App));
    tableview_OnRowClick(app->table, listener(app, i_OnRowClick, App));
    tableview_font(app->table, app->mono);
    tableview_row_height(app->table, 26);
    tableview_header_resizable(app->table, TRUE);
    tableview_header_clickable(app->table, FALSE);
    tableview_multisel(app->table, FALSE, FALSE);

    tableview_add_column_text(app->table);
    tableview_header_title(app->table, 0, "Issuer");
    tableview_column_width(app->table, 0, 180);
    tableview_column_limits(app->table, 0, 60, 400);

    tableview_add_column_text(app->table);
    tableview_header_title(app->table, 1, "Account");
    tableview_column_width(app->table, 1, 280);
    tableview_column_limits(app->table, 1, 80, 600);

    tableview_add_column_text(app->table);
    tableview_header_title(app->table, 2, "Code");
    tableview_header_align(app->table, 2, ekCENTER);
    tableview_column_width(app->table, 2, 170);
    tableview_column_limits(app->table, 2, 90, 300);

    tableview_add_column_text(app->table);
    tableview_header_title(app->table, 3, "Left");
    tableview_header_align(app->table, 3, ekCENTER);
    tableview_column_width(app->table, 3, 60);
    tableview_column_limits(app->table, 3, 50, 120);

    label_text(app->status, "Import your Aegis export (JSON) to begin. Secrets never leave memory.");
    label_multiline(app->status, TRUE);

    layout_button(toolbar, open, 0, 0);
    layout_button(toolbar, next, 1, 0);
    layout_label(toolbar, filter_label, 2, 0);
    layout_edit(toolbar, app->filter, 3, 0);
    layout_button(toolbar, del, 4, 0);
    layout_hexpand(toolbar, 5);
    layout_hsize(toolbar, 1, 130);
    layout_hmargin(toolbar, 1, 8);
    layout_hmargin(toolbar, 2, 14);
    layout_hmargin(toolbar, 3, 8);
    layout_hmargin(toolbar, 4, 8);

    layout_layout(layout, toolbar, 0, 0);
    layout_tableview(layout, app->table, 0, 1);
    layout_label(layout, app->status, 0, 2);
    layout_vexpand(layout, 1);
    layout_vmargin(layout, 0, 8);
    layout_vmargin(layout, 2, 6);
    layout_margin(layout, 10);

    panel_layout(app->panel, layout);
    window_panel(app->window, app->panel);
    window_client_size(app->window, s2df(900, 800));

    window_hotkey(app->window, ekKEY_O, ekMKEY_COMMAND, listener(app, i_OnOpen, App));
    window_hotkey(app->window, ekKEY_F, ekMKEY_COMMAND, listener(app, i_OnFilterHotkey, App));
    window_hotkey(app->window, ekKEY_C, ekMKEY_COMMAND, listener(app, i_OnCopy, App));
    window_hotkey(app->window, ekKEY_N, ekMKEY_COMMAND, listener(app, i_OnNext, App));
    window_hotkey(app->window, ekKEY_E, ekMKEY_COMMAND, listener(app, i_OnExport, App));
    window_hotkey(app->window, ekKEY_SUPR, ekMKEY_NONE, listener(app, i_OnDelete, App));

    Menu *menu = menu_create();
    {
        MenuItem *file = menuitem_create();
        menuitem_text(file, "File");

        Menu *file_sub = menu_create();
        MenuItem *open_item = menuitem_create();
        menuitem_text(open_item, "Import...");
        menuitem_OnClick(open_item, listener(app, i_OnOpen, App));
        menu_add_item(file_sub, open_item);

        MenuItem *export_item = menuitem_create();
        menuitem_text(export_item, "Export to Aegis...");
        menuitem_OnClick(export_item, listener(app, i_OnExport, App));
        menu_add_item(file_sub, export_item);

#if !defined(__APPLE__)
        menu_add_item(file_sub, menuitem_separator());

        MenuItem *quit_item = menuitem_create();
        menuitem_text(quit_item, "Quit");
        menuitem_OnClick(quit_item, listener(app, i_OnClose, App));
        menu_add_item(file_sub, quit_item);
#endif

        menuitem_submenu(file, &file_sub);
        menu_add_item(menu, file);

        MenuItem *help = menuitem_create();
        menuitem_text(help, "Help");

        Menu *help_sub = menu_create();
        MenuItem *about_item = menuitem_create();
        menuitem_text(about_item, "About Aegis Desktop");
        menuitem_OnClick(about_item, listener(app, i_OnAbout, App));
        menu_add_item(help_sub, about_item);

        menuitem_submenu(help, &help_sub);
        menu_add_item(menu, help);
    }

#if defined(__APPLE__)
    {
        Menu *app_menu = menu_create();

        MenuItem *about = menuitem_create();
        menuitem_text(about, "About Aegis Desktop");
        menuitem_OnClick(about, listener(app, i_OnAbout, App));
        menu_add_item(app_menu, about);

        menu_add_item(app_menu, menuitem_separator());

        MenuItem *quit = menuitem_create();
        menuitem_text(quit, "Quit Aegis Desktop");
        menuitem_OnClick(quit, listener(app, i_OnClose, App));
        menu_add_item(app_menu, quit);

        MenuItem *apple = menuitem_create();
        menuitem_text(apple, "");
        menuitem_submenu(apple, &app_menu);
        menu_ins_item(menu, 0, apple);
    }
#endif

    osapp_menubar(menu, app->window);

    window_show(app->window);

    {
        char saved[PATH_MAX_LEN];
        if (i_read_last_path(saved, sizeof(saved)) == TRUE)
            i_load_vault(app, saved);
    }

    return app;
}

/*---------------------------------------------------------------------------*/

void aegis_destroy(App **app)
{
    cassert_no_null(app);
    cassert_no_null(*app);

    vault_free(&(*app)->vault);
    if ((*app)->rows != NULL)
        free((*app)->rows);
    window_destroy(&(*app)->window);
    font_destroy(&(*app)->mono);
    heap_delete(app, App);
}

/*---------------------------------------------------------------------------*/

void aegis_update(App *app, const real64_t prtime, const real64_t ctime)
{
    time_t now;
    cassert_no_null(app);

    now = time(NULL);
    if (now != app->last_time)
    {
        app->last_time = now;
        if (app->nrows > 0)
            tableview_update(app->table);
    }

    unref(prtime);
    unref(ctime);
}
