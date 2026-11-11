#include <gtk/gtk.h>

#include "clipboard.h"

void clip_copy(const char *text)
{
    GtkClipboard *cb;

    if (text == NULL)
        return;

    cb = gtk_clipboard_get(GDK_SELECTION_CLIPBOARD);
    gtk_clipboard_set_text(cb, text, -1);
    gtk_clipboard_store(cb);
}
