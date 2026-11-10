/*
 * Aegis Desktop - read-only viewer for Aegis Authenticator exports.
 * NAppGUI user interface.
 */

#ifndef AEGIS_GUI_H
#define AEGIS_GUI_H

#include <core/core.hxx>

typedef struct _app_t App;

App *aegis_create(void);
void aegis_destroy(App **app);
void aegis_update(App *app, const real64_t prtime, const real64_t ctime);

#endif
