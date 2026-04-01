/*
 * PacketSanitizer - Wireshark Native C Plugin
 *
 * Copyright (C) 2026 Walter Hofstetter
 *
 * packetsanitizer_plugin.h — Wireshark epan plugin registration declarations.
 */

#ifndef PACKETSANITIZER_PLUGIN_H
#define PACKETSANITIZER_PLUGIN_H

#ifdef __cplusplus
extern "C" {
#endif

/* Called by plugin.c during plugin_register() */
void proto_register_packetsanitizer(void);
void proto_reg_handoff_packetsanitizer(void);

#ifdef __cplusplus
}
#endif

#endif /* PACKETSANITIZER_PLUGIN_H */
