/*
 * PacketSanitizer - Wireshark Native C Plugin
 *
 * Copyright (C) 2026 Walter Hofstetter
 *
 * sanitizer_engine.h — C sanitization engine using Wireshark's wtap API
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef SANITIZER_ENGINE_H
#define SANITIZER_ENGINE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <glib.h>

typedef enum {
    SANITIZE_ALL_PAYLOAD            = 0,   /* Zero all TCP/UDP payloads */
    SANITIZE_CLEARTEXT_PAYLOAD      = 1,   /* Zero only cleartext protocol payloads */
    SANITIZE_PAYLOAD_AND_ADDRESSES  = 2    /* Zero all payloads + anonymize IPs & MACs */
} sanitize_mode_t;

/*
 * Progress callback invoked from the sanitizer as it works.
 *   current     — packets processed so far
 *   total       — total packets in file (0 if unknown)
 *   status      — human-readable status string (valid only during the call)
 *   user_data   — opaque value passed to sanitizer_run()
 */
typedef void (*sanitizer_progress_cb_t)(int current, int total,
                                        const char *status, void *user_data);

typedef struct {
    gboolean  success;
    int       packets_processed;
    int       packets_written;
    int       ips_anonymized;
    int       macs_anonymized;
    char     *error_message;   /* g_strdup'd; caller must g_free() */
    char     *output_path;     /* g_strdup'd; caller must g_free() */
} sanitizer_result_t;

/*
 * Run the sanitizer on input_path, writing sanitized output to output_path.
 *
 * Returns a heap-allocated sanitizer_result_t; free with sanitizer_result_free().
 * progress_cb may be NULL.
 * *cancel_flag is checked periodically; set it to TRUE from another thread
 * to abort the run early.
 */
sanitizer_result_t *sanitizer_run(const char          *input_path,
                                  const char          *output_path,
                                  sanitize_mode_t      mode,
                                  sanitizer_progress_cb_t progress_cb,
                                  void                *user_data,
                                  volatile gboolean   *cancel_flag);

void sanitizer_result_free(sanitizer_result_t *result);

#ifdef __cplusplus
}
#endif

#endif /* SANITIZER_ENGINE_H */
