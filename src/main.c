/*
 * Aegis Desktop - read-only viewer for Aegis Authenticator exports.
 */

#include "gui.h"

#include <nappgui.h>
#include <osapp/osmain.h>

osmain_sync(.25, aegis_create, aegis_destroy, aegis_update, "", App)
