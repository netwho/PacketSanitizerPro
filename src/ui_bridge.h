/*
 * PacketSanitizer - Wireshark Native C Plugin
 *
 * Copyright (C) 2026 Walter Hofstetter
 *
 * ui_bridge.h — C-callable bridge to the Qt UI.
 *
 * All functions here have C linkage so they can be called from the
 * plain-C plugin registration code (packetsanitizer_plugin.c).
 */

#ifndef UI_BRIDGE_H
#define UI_BRIDGE_H

#ifdef __cplusplus
extern "C" {
#endif

/* Forward-declare capture_file to avoid pulling <cfile.h> (and its C++ headers)
 * inside an extern "C" block, which breaks template declarations in glib/libc++. */
typedef struct _capture_file capture_file;

/*
 * Open the PacketSanitizer start window.
 * cf  — the currently loaded capture file (may be NULL).
 */
void packetsanitizer_open_window(capture_file *cf);

/*
 * Pump the Qt event loop briefly; call this from long-running C callbacks
 * to keep the UI responsive.
 */
void packetsanitizer_pump_events(void);

#ifdef __cplusplus
}   /* extern "C" */
#endif

#endif /* UI_BRIDGE_H */
