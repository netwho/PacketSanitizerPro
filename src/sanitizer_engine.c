/*
 * PacketSanitizer - Wireshark Native C Plugin
 *
 * Copyright (C) 2026 Walter Hofstetter
 *
 * sanitizer_engine.c — Packet sanitization using Wireshark's wtap I/O API.
 *
 * Ported from sanitize_packets.py.  Three modes:
 *   SANITIZE_ALL_PAYLOAD           — zero TCP/UDP/ICMP payload bytes
 *   SANITIZE_CLEARTEXT_PAYLOAD     — zero only well-known cleartext ports
 *   SANITIZE_PAYLOAD_AND_ADDRESSES — zero all payloads + anonymize IPs & MACs
 *
 * Checksums (IP, TCP, UDP) are recomputed after any modification.
 */

#include "sanitizer_engine.h"

#include <string.h>
#include <stdio.h>

/* Pull in VERSION_MINOR so we can detect wtap API generation at compile time.
 * config.h is always generated in the build dir, which is always on the -I path. */
#include "config.h"

#include <wiretap/wtap.h>
#include <wsutil/buffer.h>
#include <glib.h>

/*
 * wtap API compatibility:
 *   WS < 4.6  — wtap_rec_init takes no size; wtap_read/wtap_dump take a
 *               separate Buffer* / guint8* for packet data; rec.data absent.
 *   WS >= 4.6 — wtap_rec_init(rec, space); packet data lives in rec.data;
 *               wtap_read and wtap_dump have no separate data argument.
 */
#if !defined(VERSION_MINOR) || VERSION_MINOR < 6
#  define WTAP_COMPAT_OLD_API 1
#endif

/* ─── Ethernet / IP constants ─────────────────────────────────────── */
#define ETH_HDR_LEN      14
#define VLAN_TAG_LEN      4
#define ETH_TYPE_IPV4  0x0800
#define ETH_TYPE_IPV6  0x86DD
#define ETH_TYPE_VLAN  0x8100
#define ETH_TYPE_QINQ  0x88A8

#define IP_PROTO_ICMP     1
#define IP_PROTO_IGMP     2
#define IP_PROTO_TCP      6
#define IP_PROTO_UDP     17

/* Cleartext protocol destination ports (same set as the Python version) */
static const guint16 CLEARTEXT_PORTS[] = {
    20, 21,         /* FTP */
    23,             /* Telnet */
    25, 587,        /* SMTP */
    53,             /* DNS */
    80, 8000, 8008, 8080, 8888,  /* HTTP */
    110, 995,       /* POP3 */
    143, 993,       /* IMAP */
    0               /* sentinel */
};

/* Sanitized payload fill pattern: 0x5341 == "SA" (Sanitized) */
static const guint8 SANITIZE_BYTE = 0x53;

/* ─── State shared across one sanitizer_run() invocation ─────────── */
typedef struct {
    sanitize_mode_t  mode;
    GHashTable      *ip_map;    /* guint32 → guint32 (host byte order) */
    guint32          ip_next;   /* next anonymized IP counter */
    GHashTable      *mac_map;   /* guint64 → guint64 (MAC in low 48 bits) */
    guint8           mac_next;  /* next anonymized MAC counter */
    int              ips_anon;
    int              macs_anon;
} run_ctx_t;

/* ─── Small helpers ───────────────────────────────────────────────── */

static inline guint16 read_be16(const guint8 *p)
{
    return (guint16)(((guint16)p[0] << 8) | p[1]);
}

static inline void write_be16(guint8 *p, guint16 v)
{
    p[0] = (guint8)(v >> 8);
    p[1] = (guint8)(v & 0xFF);
}

/* RFC 1071 one's-complement checksum over 'len' bytes */
static guint16 rfc1071_checksum(const guint8 *data, int len)
{
    guint32 sum = 0;
    int i;

    for (i = 0; i + 1 < len; i += 2)
        sum += ((guint32)data[i] << 8) | data[i + 1];
    if (len & 1)
        sum += (guint32)data[len - 1] << 8;

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return (guint16)(~sum);
}

/* Compute IP header checksum and write it back at byte offset 10 */
static void recompute_ip4_checksum(guint8 *ip, int ip_hdr_len)
{
    write_be16(ip + 10, 0);
    write_be16(ip + 10, rfc1071_checksum(ip, ip_hdr_len));
}

/* TCP/UDP checksum over the pseudo-header + segment */
static guint16 transport_checksum(const guint8 *src_ip, const guint8 *dst_ip,
                                  guint8 proto,
                                  const guint8 *seg, guint16 seg_len)
{
    guint32 sum = 0;
    int i;

    /* IPv4 pseudo-header */
    sum += ((guint32)src_ip[0] << 8) | src_ip[1];
    sum += ((guint32)src_ip[2] << 8) | src_ip[3];
    sum += ((guint32)dst_ip[0] << 8) | dst_ip[1];
    sum += ((guint32)dst_ip[2] << 8) | dst_ip[3];
    sum += (guint32)proto;
    sum += (guint32)seg_len;

    for (i = 0; i + 1 < (int)seg_len; i += 2)
        sum += ((guint32)seg[i] << 8) | seg[i + 1];
    if (seg_len & 1)
        sum += (guint32)seg[seg_len - 1] << 8;

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);

    return (guint16)(~sum);
}

/* ─── IP / MAC anonymisation ─────────────────────────────────────── */

static void anonymize_ipv4(run_ctx_t *ctx, guint8 *ip_bytes)
{
    guint32 key = ((guint32)ip_bytes[0] << 24) | ((guint32)ip_bytes[1] << 16)
                | ((guint32)ip_bytes[2] <<  8) |  ip_bytes[3];

    gpointer stored = g_hash_table_lookup(ctx->ip_map, GUINT_TO_POINTER(key));
    guint32  new_ip;

    if (!stored) {
        /* Allocate from 10.0.x.y space */
        new_ip = (10u << 24) | ((ctx->ip_next >> 8 & 0xFF) << 8) | (ctx->ip_next & 0xFF);
        ctx->ip_next++;
        g_hash_table_insert(ctx->ip_map,
                            GUINT_TO_POINTER(key),
                            GUINT_TO_POINTER(new_ip));
        ctx->ips_anon++;
    } else {
        new_ip = GPOINTER_TO_UINT(stored);
    }

    ip_bytes[0] = (new_ip >> 24) & 0xFF;
    ip_bytes[1] = (new_ip >> 16) & 0xFF;
    ip_bytes[2] = (new_ip >>  8) & 0xFF;
    ip_bytes[3] =  new_ip        & 0xFF;
}

static guint64 mac_key(const guint8 *m)
{
    return ((guint64)m[0] << 40) | ((guint64)m[1] << 32)
         | ((guint64)m[2] << 24) | ((guint64)m[3] << 16)
         | ((guint64)m[4] <<  8) |  m[5];
}

static void anonymize_mac(run_ctx_t *ctx, guint8 *mac)
{
    guint64 key = mac_key(mac);
    gpointer stored = g_hash_table_lookup(ctx->mac_map,
                                          (gconstpointer)(gintptr)key);
    guint64 new_mac_val;

    if (!stored) {
        /* 02:00:00:00:00:XX  (locally administered unicast) */
        new_mac_val = ((guint64)0x02 << 40) | (guint64)ctx->mac_next;
        ctx->mac_next++;
        g_hash_table_insert(ctx->mac_map,
                            (gpointer)(gintptr)key,
                            (gpointer)(gintptr)new_mac_val);
        ctx->macs_anon++;
    } else {
        new_mac_val = (guint64)(gintptr)stored;
    }

    mac[0] = (new_mac_val >> 40) & 0xFF;
    mac[1] = (new_mac_val >> 32) & 0xFF;
    mac[2] = (new_mac_val >> 24) & 0xFF;
    mac[3] = (new_mac_val >> 16) & 0xFF;
    mac[4] = (new_mac_val >>  8) & 0xFF;
    mac[5] =  new_mac_val        & 0xFF;
}

/* ─── Cleartext port check ───────────────────────────────────────── */

static gboolean is_cleartext_port(guint16 port)
{
    for (int i = 0; CLEARTEXT_PORTS[i]; i++) {
        if (port == CLEARTEXT_PORTS[i])
            return TRUE;
    }
    return FALSE;
}

/* ─── Single-packet sanitisation ────────────────────────────────── */

/*
 * Modify pkt_data (length caplen) in place according to the run context.
 * Returns TRUE if the packet was modified (checksums may need updating).
 */
static void sanitize_packet(run_ctx_t *ctx, guint8 *pkt, guint32 caplen)
{
    if (caplen < ETH_HDR_LEN)
        return;

    /* ── Ethernet layer ─────────────────────────────────────────── */
    if (ctx->mode == SANITIZE_PAYLOAD_AND_ADDRESSES) {
        anonymize_mac(ctx, pkt + 0);   /* dst MAC */
        anonymize_mac(ctx, pkt + 6);   /* src MAC */
    }

    guint16 ethertype = read_be16(pkt + 12);
    guint32 eth_end   = ETH_HDR_LEN;

    /* Skip VLAN tags */
    while ((ethertype == ETH_TYPE_VLAN || ethertype == ETH_TYPE_QINQ)
           && eth_end + VLAN_TAG_LEN + 2 <= caplen) {
        eth_end  += VLAN_TAG_LEN;
        ethertype = read_be16(pkt + eth_end - 2);
    }

    if (ethertype == ETH_TYPE_IPV4) {
        /* ── IPv4 ─────────────────────────────────────────────── */
        if (eth_end + 20 > caplen)
            return;

        guint8 *ip         = pkt + eth_end;
        int     ip_hdr_len = (ip[0] & 0x0F) * 4;
        if (ip_hdr_len < 20 || (guint32)(eth_end + ip_hdr_len) > caplen)
            return;

        guint8 proto = ip[9];

        /* Leave IGMP completely untouched */
        if (proto == IP_PROTO_IGMP)
            return;

        /* Anonymize IP addresses */
        if (ctx->mode == SANITIZE_PAYLOAD_AND_ADDRESSES) {
            anonymize_ipv4(ctx, ip + 12);  /* src IP */
            anonymize_ipv4(ctx, ip + 16);  /* dst IP */
        }

        guint8 *transport  = ip + ip_hdr_len;
        guint32 trans_off  = eth_end + ip_hdr_len;

        if (proto == IP_PROTO_TCP && trans_off + 20 <= caplen) {
            guint8 *tcp          = transport;
            int     tcp_hdr_len  = ((tcp[12] >> 4) & 0x0F) * 4;
            guint16 sport        = read_be16(tcp + 0);
            guint16 dport        = read_be16(tcp + 2);
            guint32 payload_off  = trans_off + tcp_hdr_len;
            guint32 payload_len  = caplen - payload_off;

            gboolean sanitize_payload = FALSE;
            if (ctx->mode == SANITIZE_ALL_PAYLOAD ||
                ctx->mode == SANITIZE_PAYLOAD_AND_ADDRESSES) {
                sanitize_payload = TRUE;
            } else if (ctx->mode == SANITIZE_CLEARTEXT_PAYLOAD) {
                sanitize_payload = is_cleartext_port(sport)
                                || is_cleartext_port(dport);
            }

            if (sanitize_payload && payload_len > 0) {
                memset(pkt + payload_off, SANITIZE_BYTE, payload_len);
            }

            if (sanitize_payload || ctx->mode == SANITIZE_PAYLOAD_AND_ADDRESSES) {
                /* Recompute TCP checksum */
                write_be16(tcp + 16, 0);
                guint16 tcp_total = (guint16)(caplen - trans_off);
                write_be16(tcp + 16,
                    transport_checksum(ip + 12, ip + 16,
                                       IP_PROTO_TCP, tcp, tcp_total));
            }

        } else if (proto == IP_PROTO_UDP && trans_off + 8 <= caplen) {
            guint8 *udp         = transport;
            guint16 sport       = read_be16(udp + 0);
            guint16 dport       = read_be16(udp + 2);
            guint32 payload_off = trans_off + 8;
            guint32 payload_len = caplen - payload_off;

            gboolean sanitize_payload = FALSE;
            if (ctx->mode == SANITIZE_ALL_PAYLOAD ||
                ctx->mode == SANITIZE_PAYLOAD_AND_ADDRESSES) {
                sanitize_payload = TRUE;
            } else if (ctx->mode == SANITIZE_CLEARTEXT_PAYLOAD) {
                sanitize_payload = is_cleartext_port(sport)
                                || is_cleartext_port(dport);
            }

            if (sanitize_payload && payload_len > 0) {
                memset(pkt + payload_off, SANITIZE_BYTE, payload_len);
            }

            if (sanitize_payload || ctx->mode == SANITIZE_PAYLOAD_AND_ADDRESSES) {
                /* Recompute UDP checksum */
                write_be16(udp + 6, 0);
                guint16 udp_len = read_be16(udp + 4);
                if (udp_len >= 8) {
                    write_be16(udp + 6,
                        transport_checksum(ip + 12, ip + 16,
                                           IP_PROTO_UDP, udp, udp_len));
                }
            }

        } else if (proto == IP_PROTO_ICMP && trans_off + 4 <= caplen) {
            /* Sanitize ICMP payload when mode calls for all-payload */
            if (ctx->mode == SANITIZE_ALL_PAYLOAD ||
                ctx->mode == SANITIZE_PAYLOAD_AND_ADDRESSES) {
                guint32 icmp_hdr = 8; /* standard ICMP header */
                if (trans_off + icmp_hdr < caplen) {
                    guint32 payload_len = caplen - trans_off - icmp_hdr;
                    memset(pkt + trans_off + icmp_hdr, SANITIZE_BYTE, payload_len);
                }
            }
        }

        /* Recompute IP header checksum after any modification */
        recompute_ip4_checksum(ip, ip_hdr_len);

    } else if (ethertype == ETH_TYPE_IPV6) {
        /* ── IPv6 (40-byte fixed header) ──────────────────────── */
        if (eth_end + 40 > caplen)
            return;

        guint8 *ip6 = pkt + eth_end;
        guint8  proto = ip6[6];   /* Next Header */

        /* Leave IGMP/MLD alone */
        if (proto == IP_PROTO_IGMP || proto == 58 /* ICMPv6 */)
            return;

        if (ctx->mode == SANITIZE_PAYLOAD_AND_ADDRESSES) {
            /* Anonymize IPv6 src (bytes 8-23) and dst (bytes 24-39) */
            /* For simplicity we map the full address via the last 4 bytes
             * as a key; a full 128-bit mapping is a future enhancement. */
            anonymize_ipv4(ctx, ip6 +  8 + 12);   /* last 4 bytes of src */
            anonymize_ipv4(ctx, ip6 + 24 + 12);   /* last 4 bytes of dst */
        }

        guint32 trans_off = eth_end + 40;

        if (proto == IP_PROTO_TCP && trans_off + 20 <= caplen) {
            guint8  *tcp         = pkt + trans_off;
            int      tcp_hdr_len = ((tcp[12] >> 4) & 0x0F) * 4;
            guint16  sport       = read_be16(tcp + 0);
            guint16  dport       = read_be16(tcp + 2);
            guint32  payload_off = trans_off + tcp_hdr_len;
            guint32  payload_len = caplen - payload_off;

            gboolean sanitize_payload = FALSE;
            if (ctx->mode == SANITIZE_ALL_PAYLOAD ||
                ctx->mode == SANITIZE_PAYLOAD_AND_ADDRESSES) {
                sanitize_payload = TRUE;
            } else if (ctx->mode == SANITIZE_CLEARTEXT_PAYLOAD) {
                sanitize_payload = is_cleartext_port(sport)
                                || is_cleartext_port(dport);
            }
            if (sanitize_payload && payload_len > 0)
                memset(pkt + payload_off, SANITIZE_BYTE, payload_len);

        } else if (proto == IP_PROTO_UDP && trans_off + 8 <= caplen) {
            guint8  *udp         = pkt + trans_off;
            guint16  sport       = read_be16(udp + 0);
            guint16  dport       = read_be16(udp + 2);
            guint32  payload_off = trans_off + 8;
            guint32  payload_len = caplen - payload_off;

            gboolean sanitize_payload = FALSE;
            if (ctx->mode == SANITIZE_ALL_PAYLOAD ||
                ctx->mode == SANITIZE_PAYLOAD_AND_ADDRESSES) {
                sanitize_payload = TRUE;
            } else if (ctx->mode == SANITIZE_CLEARTEXT_PAYLOAD) {
                sanitize_payload = is_cleartext_port(sport)
                                || is_cleartext_port(dport);
            }
            if (sanitize_payload && payload_len > 0)
                memset(pkt + payload_off, SANITIZE_BYTE, payload_len);
        }
    }
    /* Other ethertypes (ARP, etc.) are passed through unchanged. */
}

/* ─── Public API ─────────────────────────────────────────────────── */

sanitizer_result_t *sanitizer_run(const char          *input_path,
                                  const char          *output_path,
                                  sanitize_mode_t      mode,
                                  sanitizer_progress_cb_t progress_cb,
                                  void                *user_data,
                                  volatile gboolean   *cancel_flag)
{
    sanitizer_result_t *res = g_new0(sanitizer_result_t, 1);
    res->output_path = g_strdup(output_path);

    /* ── Open input file ─────────────────────────────────────── */
    int    err      = 0;
    char  *err_info = NULL;

    wtap *wth = wtap_open_offline(input_path, WTAP_TYPE_AUTO,
                                  &err, &err_info, FALSE);
    if (!wth) {
        res->success       = FALSE;
        res->error_message = err_info
            ? g_strdup_printf("Cannot open input: %s", err_info)
            : g_strdup_printf("Cannot open input (err=%d)", err);
        g_free(err_info);
        return res;
    }

    /* ── Open output dumper ──────────────────────────────────── */
    int file_type = wtap_file_type_subtype(wth);

    wtap_dump_params params = WTAP_DUMP_PARAMS_INIT;
    wtap_dump_params_init(&params, wth);

    bool needs_reload = false;
    wtap_dumper *pdh = wtap_dump_open(output_path, file_type,
                                      WTAP_UNCOMPRESSED, &params,
                                      &err, &err_info);
    if (!pdh) {
        res->success       = FALSE;
        res->error_message = err_info
            ? g_strdup_printf("Cannot open output: %s", err_info)
            : g_strdup_printf("Cannot open output (err=%d)", err);
        g_free(err_info);
        wtap_dump_params_cleanup(&params);
        wtap_close(wth);
        return res;
    }

    /* ── Initialise state ────────────────────────────────────── */
    run_ctx_t ctx = {
        .mode     = mode,
        .ip_map   = g_hash_table_new(g_direct_hash, g_direct_equal),
        .ip_next  = 1,
        .mac_map  = g_hash_table_new(g_direct_hash, g_direct_equal),
        .mac_next = 1,
        .ips_anon = 0,
        .macs_anon= 0
    };

    /* ── Read / process / write loop ─────────────────────────── */
    wtap_rec  rec;
#ifdef WTAP_COMPAT_OLD_API
    wtap_rec_init(&rec);
    Buffer    buf;
    ws_buffer_init(&buf, 1500);
#else
    wtap_rec_init(&rec, 1500);
#endif

    int64_t offset = 0;
    int     processed = 0;
    int     written   = 0;
    char    status_buf[128];

    if (progress_cb)
        progress_cb(0, 0, "Starting sanitization…", user_data);

#ifdef WTAP_COMPAT_OLD_API
    while (wtap_read(wth, &rec, &buf, &err, &err_info, &offset)) {
#else
    while (wtap_read(wth, &rec, &err, &err_info, &offset)) {
#endif
        if (cancel_flag && *cancel_flag)
            break;

        if (rec.rec_type == REC_TYPE_PACKET) {
#ifdef WTAP_COMPAT_OLD_API
            guint8  *data   = ws_buffer_start_ptr(&buf);
#else
            guint8  *data   = ws_buffer_start_ptr(&rec.data);
#endif
            guint32  caplen = rec.rec_header.packet_header.caplen;
            int      encap  = rec.rec_header.packet_header.pkt_encap;

            /* Only process Ethernet frames; pass everything else through */
            if (encap == WTAP_ENCAP_ETHERNET && data && caplen > 0)
                sanitize_packet(&ctx, data, caplen);
        }

        /* Write the (possibly modified) record */
#ifdef WTAP_COMPAT_OLD_API
        if (!wtap_dump(pdh, &rec, ws_buffer_start_ptr(&buf), &err, &err_info)) {
#else
        if (!wtap_dump(pdh, &rec, &err, &err_info)) {
#endif
            res->success       = FALSE;
            res->error_message = err_info
                ? g_strdup_printf("Write error at packet %d: %s", processed, err_info)
                : g_strdup_printf("Write error at packet %d (err=%d)", processed, err);
            g_free(err_info);
            goto cleanup;
        }
        written++;

        processed++;
        if (progress_cb && (processed % 1000 == 0 || processed == 1)) {
            snprintf(status_buf, sizeof(status_buf),
                     "Processing packet %d…", processed);
            progress_cb(processed, 0, status_buf, user_data);
        }
    }

    if (err != 0 && !(cancel_flag && *cancel_flag)) {
        res->success       = FALSE;
        res->error_message = err_info
            ? g_strdup_printf("Read error at packet %d: %s", processed, err_info)
            : g_strdup_printf("Read error at packet %d (err=%d)", processed, err);
        g_free(err_info);
        goto cleanup;
    }

    res->success = TRUE;

cleanup:
    wtap_rec_cleanup(&rec);
#ifdef WTAP_COMPAT_OLD_API
    ws_buffer_free(&buf);
#endif

    if (!wtap_dump_close(pdh, &needs_reload, &err, &err_info)) {
        if (res->success) {
            res->success       = FALSE;
            res->error_message = err_info
                ? g_strdup_printf("Close error: %s", err_info)
                : g_strdup_printf("Close error (err=%d)", err);
        }
        g_free(err_info);
    }

    wtap_dump_params_cleanup(&params);
    wtap_close(wth);

    g_hash_table_destroy(ctx.ip_map);
    g_hash_table_destroy(ctx.mac_map);

    res->packets_processed = processed;
    res->packets_written   = written;
    res->ips_anonymized    = ctx.ips_anon;
    res->macs_anonymized   = ctx.macs_anon;

    if (progress_cb && res->success) {
        snprintf(status_buf, sizeof(status_buf),
                 "Done — %d packets sanitized.", written);
        progress_cb(processed, processed, status_buf, user_data);
    }

    return res;
}

void sanitizer_result_free(sanitizer_result_t *result)
{
    if (!result) return;
    g_free(result->error_message);
    g_free(result->output_path);
    g_free(result);
}
