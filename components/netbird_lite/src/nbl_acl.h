// SPDX-License-Identifier: Apache-2.0
// Inbound firewall: rule matching, tracking of connections opened by the device and a fragment
// verdict cache. No dependencies, so it can be unit-tested on the host. Not thread-safe: the
// caller serialises all calls on one nbl_acl_state_t (netbird-lite: the lwIP TCP/IP thread).
#pragma once
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef ESP_PLATFORM
#include "sdkconfig.h"
#endif
#ifndef CONFIG_NBL_CT_ENTRIES
#define CONFIG_NBL_CT_ENTRIES 16 /* host builds, or CONFIG_NBL_ACL_ENFORCE disabled */
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define NBL_ACL_ACCEPT 0
#define NBL_ACL_DROP 1

typedef struct {
    uint32_t src;   /* IPv4, network byte order; mask 0 = any source */
    uint32_t mask;
    uint8_t proto;  /* 0 = any, otherwise IP protocol number (6 TCP, 17 UDP, 1 ICMP) */
    uint16_t p0;    /* destination port range p0..p1, 0/0 = any (TCP/UDP only) */
    uint16_t p1;
    uint8_t action; /* NBL_ACL_ACCEPT (0, the zero-initialised default) or NBL_ACL_DROP;
                       any other value counts as DROP */
} nbl_acl_rule_t;

/** true = the packet may pass: no DROP rule matches and at least one ACCEPT rule matches.
 *  rules == NULL or n == 0 -> nothing passes. */
bool nbl_acl_match(const nbl_acl_rule_t *rules, size_t n, uint32_t src, uint8_t proto,
                   bool has_port, uint16_t dport);

/** Packet bytes read by nbl_acl_track()/nbl_acl_check(): IPv4 header with options plus a
 *  minimal TCP header. Pass min(packet length, NBL_ACL_HDR_MAX) bytes. */
#define NBL_ACL_HDR_MAX (60 + 20)

#define NBL_ACL_FRAG_ENTRIES 8

typedef struct {
    uint32_t ip;    /* remote address, network byte order */
    uint32_t seen;  /* last packet in either direction (seconds) */
    uint16_t rport; /* remote port; ICMP: echo identifier */
    uint16_t lport; /* local port; ICMP: echo identifier */
    uint8_t proto;  /* 0 = free entry */
    uint8_t flags;  /* TCP: FIN/RST seen */
} nbl_ct_entry_t;

typedef struct {
    uint32_t src;
    uint32_t since; /* when the first fragment passed (seconds); not refreshed */
    uint16_t id;    /* IPv4 identification */
    uint8_t proto;
    uint8_t used;
} nbl_frag_entry_t;

typedef struct {
    uint32_t local_ip; /* our NetBird address, network byte order; 0 = nothing passes */
    nbl_ct_entry_t ct[CONFIG_NBL_CT_ENTRIES];
    nbl_frag_entry_t frag[NBL_ACL_FRAG_ENTRIES];
} nbl_acl_state_t;

/** Forgets all tracked connections and fragments and sets our address. */
void nbl_acl_init(nbl_acl_state_t *st, uint32_t local_ip);

/** Outbound IPv4 packet (pkt: its first len bytes, see NBL_ACL_HDR_MAX). TCP/UDP from our
 *  address and ICMP echo requests are tracked so that their replies pass nbl_acl_check(); the
 *  least recently used entry is replaced when the table is full. now: monotonic clock in
 *  seconds. Idle timeouts: TCP 2 h (10 s after RST or FIN in both directions), UDP 120 s,
 *  ICMP 30 s. */
void nbl_acl_track(nbl_acl_state_t *st, const uint8_t *pkt, size_t len, uint32_t now);

/** Inbound IPv4 packet: true = pass. In this order: the destination must be our address, a
 *  reply to a tracked connection passes, then any matching DROP rule drops and any matching
 *  ACCEPT rule passes, everything else is dropped. A trailing fragment passes only within 30 s
 *  of a passed first fragment of the same datagram (source, identification, protocol). */
bool nbl_acl_check(nbl_acl_state_t *st, const nbl_acl_rule_t *rules, size_t n,
                   const uint8_t *pkt, size_t len, uint32_t now);

#ifdef __cplusplus
}
#endif
