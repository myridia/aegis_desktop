#include <windows.h>

#include "clipboard.h"

void clip_copy(const char *text)
{
    int n;
    HGLOBAL h;
    wchar_t *buf;

    if (text == NULL)
        return;

    n = MultiByteToWideChar(CP_UTF8, 0, text, -1, NULL, 0);
    if (n <= 0)
        return;

    h = GlobalAlloc(GMEM_MOVEABLE, (SIZE_T)n * sizeof(wchar_t));
    if (h == NULL)
        return;

    buf = (wchar_t *)GlobalLock(h);
    if (buf == NULL)
    {
        GlobalFree(h);
        return;
    }

    MultiByteToWideChar(CP_UTF8, 0, text, -1, buf, n);
    GlobalUnlock(h);

    if (OpenClipboard(NULL) == FALSE)
    {
        GlobalFree(h);
        return;
    }

    EmptyClipboard();
    SetClipboardData(CF_UNICODETEXT, h);
    CloseClipboard();
}
