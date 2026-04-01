/*
 * PacketSanitizer - Wireshark Native C Plugin
 *
 * Copyright (C) 2026 Walter Hofstetter
 *
 * packetsanitizer_plugin.c — Wireshark epan plugin registration.
 *
 * Registers the "PacketSanitizer" protocol entry, adds a single
 * "Tools > PacketSanitizer > Open…" menu item, and dispatches to
 * the Qt UI via ui_bridge.
 */

#include "packetsanitizer_plugin.h"
#include "ui_bridge.h"

#include <epan/proto.h>
#include <epan/plugin_if.h>
#include <wsutil/wslog.h>
#include <cfile.h>

#define WS_LOG_DOMAIN "packetsanitizer"

/* Embedded version string — detectable via strings(1) and by installers */
static const char packetsanitizer_version_string[] =
    "PacketSanitizer Pro v.0.1.1";

/* Protocol handle */
static int proto_packetsanitizer = -1;

/* Menu handle */
static ext_menu_t *g_menu = NULL;

/* ------------------------------------------------------------------ */
/* Helper: extract capture_file* from plugin_if callback               */
/* ------------------------------------------------------------------ */
static void *extract_capture_file_cb(capture_file *cf, void *user_data)
{
    (void)user_data;
    return (void *)cf;
}

/* ------------------------------------------------------------------ */
/* Menu callback — invoked when user clicks the menu item             */
/* ------------------------------------------------------------------ */
static void open_window_cb(ext_menubar_gui_type gui_type,
                           void *gui_object,
                           void *user_data)
{
    (void)gui_type;
    (void)gui_object;
    (void)user_data;

    capture_file *cf =
        (capture_file *)plugin_if_get_capture_file(extract_capture_file_cb, NULL);

    if (cf)
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO,
               "Opening PacketSanitizer window (capture: %s, packets: %u)",
               cf->filename ? cf->filename : "<unknown>", cf->count);
    else
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO,
               "Opening PacketSanitizer window (no capture loaded)");

    packetsanitizer_open_window(cf);
}

/* ------------------------------------------------------------------ */
/* proto_register_packetsanitizer                                      */
/* ------------------------------------------------------------------ */
void proto_register_packetsanitizer(void)
{
    /* Guard against double registration */
    if (proto_get_id_by_filter_name("packetsanitizer") != -1) {
        ws_log(WS_LOG_DOMAIN, LOG_LEVEL_WARNING,
               "PacketSanitizer already registered — skipping duplicate.");
        return;
    }

    proto_packetsanitizer = proto_register_protocol(
        "PacketSanitizer Pro (Author: Walter Hofstetter, "
        "https://github.com/netwho/PacketSanitizer)",
        "PacketSanitizer Pro",
        "packetsanitizer"
    );

    /* Register Tools menu entry */
    g_menu = ext_menubar_register_menu(
        proto_packetsanitizer,
        "PacketSanitizer Pro",
        TRUE   /* is_plugin */
    );

    ext_menubar_set_parentmenu(g_menu, "Tools");

    ext_menubar_add_entry(g_menu,
                          "Open PacketSanitizer Pro…",
                          "Sanitize the current capture buffer",
                          open_window_cb,
                          NULL);

    ws_log(WS_LOG_DOMAIN, LOG_LEVEL_INFO,
           "%s registered (proto_id=%d)",
           packetsanitizer_version_string, proto_packetsanitizer);
}

/* ------------------------------------------------------------------ */
/* proto_reg_handoff_packetsanitizer                                   */
/* ------------------------------------------------------------------ */
void proto_reg_handoff_packetsanitizer(void)
{
    /* Nothing to hand off — we are not a packet dissector. */
}
