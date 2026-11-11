#import <Cocoa/Cocoa.h>

#include "clipboard.h"

void clip_copy(const char *text)
{
    if (text == NULL)
        return;

    @autoreleasepool
    {
        NSString *string = [NSString stringWithUTF8String:text];
        if (string == nil)
            return;

        NSPasteboard *pasteboard = [NSPasteboard generalPasteboard];
        [pasteboard clearContents];
        [pasteboard setString:string forType:NSPasteboardTypeString];
    }
}
