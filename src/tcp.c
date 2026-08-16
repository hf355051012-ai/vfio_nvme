#include <stddef.h>
#include "tcp.h"
#include "ip.h"
#include "netif.h"
#include "arp.h"
#include "net_buf.h"
#include "net.h"
#include "uart.h"
#include "timer.h"
#include "timestamp.h"
#include "cache.h"
#include "job.h"
#include "smp.h"

uint64_t g_tcp_copy2_ns = 0, g_tcp_copy2_bytes = 0;
uint64_t g_tcp_copy3_ns = 0, g_tcp_copy3_bytes = 0;
void tcp_copy_stats_get(uint64_t *c2_ns, uint64_t *c2_by,
                        uint64_t *c3_ns, uint64_t *c3_by)
{
    if (c2_ns) *c2_ns = g_tcp_copy2_ns;
    if (c2_by) *c2_by = g_tcp_copy2_bytes;
    if (c3_ns) *c3_ns = g_tcp_copy3_ns;
    if (c3_by) *c3_by = g_tcp_copy3_bytes;
}

#define TCP_OFF_SRC_PORT    offsetof(tcp_header_t, src_port)
#define TCP_OFF_DST_PORT    offsetof(tcp_header_t, dst_port)
#define TCP_OFF_SEQ         offsetof(tcp_header_t, seq)
#define TCP_OFF_ACK         offsetof(tcp_header_t, ack)
#define TCP_OFF_DATA_OFFSET offsetof(tcp_header_t, data_offset)
#define TCP_OFF_FLAGS       offsetof(tcp_header_t, flags)
#define TCP_OFF_WINDOW      offsetof(tcp_header_t, window)
#define TCP_OFF_CHECKSUM    offsetof(tcp_header_t, checksum)
#define TCP_OFF_URGENT      offsetof(tcp_header_t, urgent_ptr)

/* TCPオプションのkind値 (RFC793/RFC879/RFC7323)。 */
#define TCP_OPT_KIND_END    0u
#define TCP_OPT_KIND_NOP    1u
#define TCP_OPT_KIND_MSS    2u
#define TCP_OPT_KIND_WSCALE 3u

#define TCP_MSS_LOCAL           10182u
#define TCP_MSS_DEFAULT_RFC879   536u  /* 相手がMSSオプションを付けなかった場合の既定値 */

#define TCP_MAX_CONNS 12u

#define TCP_RX_BUF_SIZE (16u * 1024u * 1024u)

#define TCP_RECV_NOACK_ACK_THRESHOLD_MSS 2u

#define TCP_RCV_WSCALE 4u

#define TCP_INITIAL_RTO_MS      500u
#define TCP_RTO_MIN_MS           200u
#define TCP_MAX_RTO_MS         8000u
#define TCP_MAX_RETRIES            5

#define TCP_SEND_OVERALL_TIMEOUT_MS 30000u  /* tcp_send()全体(複数セグメント/再送込み)の上限 */
#define TCP_CLOSE_FIN_WAIT_MS        2000u  /* 自分のFINがACKされた後、相手のFINを待つ時間 */

#define TCP_OOO_SLOTS 64u

#define TCP_ASYNC_SLOTS 16u

#define TCP_ASYNC_SLOTS_MLX5_EXTRA    16u
#define TCP_ASYNC_MLX5_OVERFLOW_CONNS 8u

#define TCP_ASYNC_SHORT_MAX_LEN 512u
#define TCP_ASYNC_SHORT_SLOTS   16u

volatile uint32_t g_tcp_retransmit_count[SMP_MAX_CORES];

volatile uint32_t g_tcp_ack_threshold = 4u;

/* 受信循環バッファの容量(tcp.h、パイプライン受信の in-flight 上限計算に使う)。 */
uint32_t tcp_rx_buf_size(void)
{
    return TCP_RX_BUF_SIZE;
}

/* 順序入れ替わりセグメント1件分の保持スロット(tcp_priv_t.ooo[]参照)。 */
typedef struct {
    volatile int      valid;
    volatile uint32_t seq;
    uint8_t           buf[TCP_MSS_LOCAL];
    volatile uint16_t len;
} tcp_ooo_slot_t;

typedef struct {
    uint32_t seq;      /* このセグメントの先頭seq */
    uint16_t len;
    uint8_t  buf[TCP_ASYNC_MAX_LEN];
    const uint8_t *ref;
    uint64_t sent_at;  /* 直近の送信(初回または再送)時刻 */
    uint32_t rto_ms;
    int      retries;
} tcp_async_slot_t;

typedef struct {
    uint32_t seq;
    uint16_t len;
    uint8_t  buf[TCP_ASYNC_SHORT_MAX_LEN];
    uint64_t sent_at;
    uint32_t rto_ms;
    int      retries;
} tcp_async_short_slot_t;

typedef struct {
    volatile int      ack_received;
    volatile uint32_t expected_ack;

    volatile uint32_t snd_una;
    volatile int      ack_advanced;

    uint64_t srtt_us;
    uint64_t rttvar_us;
    uint32_t rto_ms;

    uint32_t cwnd;
    uint32_t ssthresh;

    uint8_t           rx_buf[TCP_RX_BUF_SIZE];
    volatile uint32_t rx_read;
    volatile uint32_t rx_count;
    volatile int      fin_received;

    tcp_recv_upcall_fn recv_upcall;
    void              *recv_upcall_ctx;

    int      wscale_enabled;
    uint8_t  snd_wscale;

    uint32_t          unacked_full_segments;

    uint32_t          unacked_consumed_bytes;

    tcp_ooo_slot_t ooo[TCP_OOO_SLOTS];

    tcp_async_slot_t async_slots[TCP_ASYNC_SLOTS];
    unsigned          async_head;
    unsigned          async_count;
    int               async_overflow_idx;
    unsigned          async_cap;
    uint8_t           async_overflow_ever_init;

    tcp_async_short_slot_t async_short_slots[TCP_ASYNC_SHORT_SLOTS];
    unsigned                async_short_head;
    unsigned                async_short_count;

    volatile int      in_bulk_send;

    uint32_t connect_attempt;
    uint32_t connect_rto_ms;
    uint64_t connect_sent_at;
} tcp_priv_t;

static tcp_conn_t *s_conns[SMP_MAX_CORES][TCP_MAX_CONNS];
static tcp_priv_t  s_priv[SMP_MAX_CORES][TCP_MAX_CONNS];

#define TCP_TIMEWAIT_MAX 4u
#define TCP_TIMEWAIT_MS  4000u  /* TCP_CLOSE_FIN_WAIT_MSより十分長い安全マージン */

typedef struct {
    int      in_use;
    uint32_t local_ip;
    uint16_t local_port;
    uint32_t remote_ip;
    uint16_t remote_port;
    uint32_t local_seq;      /* 応答ACKのSEQフィールドに使う自分のFIN後のseq(不変) */
    uint64_t started_ticks;  /* TIME_WAIT開始時刻(TCP_TIMEWAIT_MS、timeout_ms()で判定) */
} tcp_timewait_t;

#define TCP_TIMEWAIT_TOTAL (TCP_TIMEWAIT_MAX * SMP_MAX_CORES)
static tcp_timewait_t s_timewait[TCP_TIMEWAIT_TOTAL];
static smp_spinlock_t s_timewait_lock;

static tcp_timewait_t *tcp_timewait_find(uint32_t remote_ip, uint16_t remote_port, uint16_t local_port)
{
    smp_spin_lock(&s_timewait_lock);
    for (unsigned i = 0; i < TCP_TIMEWAIT_TOTAL; i++) {
        if (s_timewait[i].in_use &&
            s_timewait[i].remote_ip == remote_ip &&
            s_timewait[i].remote_port == remote_port &&
            s_timewait[i].local_port == local_port) {
            smp_spin_unlock(&s_timewait_lock);
            return &s_timewait[i];
        }
    }
    smp_spin_unlock(&s_timewait_lock);
    return NULL;
}

static void tcp_timewait_register(uint32_t local_ip, uint16_t local_port,
                                   uint32_t remote_ip, uint16_t remote_port,
                                   uint32_t local_seq)
{
    smp_spin_lock(&s_timewait_lock);
    int slot = -1;
    for (unsigned i = 0; i < TCP_TIMEWAIT_TOTAL; i++) {
        if (!s_timewait[i].in_use) { slot = (int)i; break; }
    }
    if (slot < 0) slot = 0;  /* 空きが無ければ一番古い(先頭)のエントリを再利用する */
    s_timewait[slot].in_use       = 1;
    s_timewait[slot].local_ip     = local_ip;
    s_timewait[slot].local_port   = local_port;
    s_timewait[slot].remote_ip    = remote_ip;
    s_timewait[slot].remote_port  = remote_port;
    s_timewait[slot].local_seq    = local_seq;
    s_timewait[slot].started_ticks = timer_now();
    smp_spin_unlock(&s_timewait_lock);
}

/* 期限切れエントリを掃除する(tcp_poll_once()から毎回呼ぶ軽量処理)。 */
static void tcp_timewait_reap(void)
{
    smp_spin_lock(&s_timewait_lock);
    for (unsigned i = 0; i < TCP_TIMEWAIT_TOTAL; i++) {
        if (s_timewait[i].in_use && timeout_ms(s_timewait[i].started_ticks, TCP_TIMEWAIT_MS)) {
            s_timewait[i].in_use = 0;
        }
    }
    smp_spin_unlock(&s_timewait_lock);
}

typedef struct {
    int         in_use;
    uint16_t    port;
    netif_t  *bound_ctx;    /* NULL = インターフェースを問わず受け付ける */
    tcp_conn_t *accept_conn;  /* tcp_accept_begin()が渡してきたconn */
    volatile int accept_ready; /* ESTABLISHEDになった = 1 */
} tcp_listener_slot_t;

#define TCP_LISTENER_TOTAL (TCP_MAX_LISTENERS * SMP_MAX_CORES)
static tcp_listener_slot_t s_listeners[TCP_LISTENER_TOTAL];
static smp_spinlock_t      s_listener_lock;

static tcp_listener_slot_t *tcp_listener_for(int listener)
{
    if (listener < 0 || (unsigned)listener >= TCP_LISTENER_TOTAL) return NULL;
    if (!s_listeners[listener].in_use) return NULL;
    return &s_listeners[listener];
}

static tcp_priv_t *tcp_priv_for(tcp_conn_t *conn)
{
    unsigned core = conn->owner_core;
    for (unsigned i = 0; i < TCP_MAX_CONNS; i++) {
        if (s_conns[core][i] == conn) {
            return &s_priv[core][i];
        }
    }
    return NULL;
}

/* 空きスロットを探す。無ければ-1。 */
static int tcp_find_free_slot(void)
{
    unsigned core = smp_core_index();
    for (unsigned i = 0; i < TCP_MAX_CONNS; i++) {
        if (s_conns[core][i] == NULL) {
            return (int)i;
        }
    }
    return -1;
}

static unsigned tcp_conn_slot(const tcp_conn_t *conn)
{
    /* tcp_priv_for()と同じ理由でconn->owner_coreを使う(上記コメント参照)。 */
    unsigned core = conn->owner_core;
    for (unsigned i = 0; i < TCP_MAX_CONNS; i++) {
        if (s_conns[core][i] == conn) {
            return i;
        }
    }
    return TCP_MAX_CONNS;
}

uint32_t tcp_conn_arg(const tcp_conn_t *conn, uint32_t value)
{
    return ((uint32_t)tcp_conn_slot(conn) << 24) | (value & 0x00FFFFFFu);
}

static inline int tcp_seq_lt(uint32_t a, uint32_t b) { return (int32_t)(a - b) < 0; }
static inline int tcp_seq_gt(uint32_t a, uint32_t b) { return (int32_t)(a - b) > 0; }

static void tcp_rx_buf_push(tcp_priv_t *priv, const volatile uint8_t *data, uint16_t data_len)
{
    uint32_t write_pos = (uint32_t)((priv->rx_read + priv->rx_count) % TCP_RX_BUF_SIZE);

    uint32_t first_len = TCP_RX_BUF_SIZE - write_pos;
    if (first_len > data_len) first_len = data_len;

    uint64_t cpt0 = timer_now();
    volatile_fast_copy((volatile uint8_t *)&priv->rx_buf[write_pos], data, first_len);
    if (first_len < data_len) {
        volatile_fast_copy((volatile uint8_t *)&priv->rx_buf[0], data + first_len,
                            (uint16_t)(data_len - first_len));
    }
    g_tcp_copy2_ns    += get_ns_from(cpt0);
    g_tcp_copy2_bytes += data_len;
    priv->rx_count = priv->rx_count + data_len;
}

static void tcp_deliver_data(tcp_priv_t *priv, const volatile uint8_t *data, uint16_t data_len)
{
    if (priv->recv_upcall) { // tcp_set_recv_upcall()で設定されるhandler
        // -> nvmet_io_rx_upcall(nvmet.c) / nvme_read_rx_upcall(nvme.c)
        priv->recv_upcall(priv->recv_upcall_ctx, data, data_len);
    } else {
        tcp_rx_buf_push(priv, data, data_len);
    }
}

void tcp_set_recv_upcall(tcp_conn_t *conn, tcp_recv_upcall_fn fn, void *ctx)
{
    tcp_priv_t *priv = tcp_priv_for(conn);
    if (!priv) return;
    priv->recv_upcall     = fn;
    priv->recv_upcall_ctx = ctx;
}

void tcp_clear_recv_upcall(tcp_conn_t *conn)
{
    tcp_priv_t *priv = tcp_priv_for(conn);
    if (!priv) return;
    priv->recv_upcall     = NULL;
    priv->recv_upcall_ctx = NULL;
}

static void tcp_rtt_update(tcp_priv_t *priv, uint64_t measured_ticks)
{
    uint64_t measured_us = ticks_to_us(measured_ticks);

    if (priv->srtt_us == 0) {
        priv->srtt_us = measured_us;
        priv->rttvar_us = measured_us / 2u;
    } else {
        int64_t delta = (int64_t)measured_us - (int64_t)priv->srtt_us;
        uint64_t abs_delta = (uint64_t)((delta < 0) ? -delta : delta);
        priv->rttvar_us = (priv->rttvar_us * 3u + abs_delta) / 4u;
        priv->srtt_us = (priv->srtt_us * 7u + measured_us) / 8u;
    }

    uint64_t rto_us = priv->srtt_us + 4u * priv->rttvar_us;
    uint32_t rto_ms = (uint32_t)(rto_us / 1000u);
    if (rto_ms < TCP_RTO_MIN_MS) rto_ms = TCP_RTO_MIN_MS;
    if (rto_ms > TCP_MAX_RTO_MS) rto_ms = TCP_MAX_RTO_MS;
    priv->rto_ms = rto_ms;
}

static uint8_t s_seg_bufs[SMP_MAX_CORES][ETH_TX_RING_SIZE][IP_PAYLOAD_OFFSET + TCP_HDR_LEN + 8 + TCP_MSS_LOCAL]
    __attribute__((aligned(64)));

static int tcp_send_segment(tcp_conn_t *conn, tcp_priv_t *priv, uint8_t flags,
                             const void *data, uint16_t data_len)
{
    unsigned core = smp_core_index();

    netif_t *conn_ctx = netif_find_by_ip(conn->local_ip);
    if (conn_ctx) {
        netif_activate(conn_ctx);
    }

    uint8_t dst_mac[ETH_ALEN];
    if (arp_cache_lookup(conn->remote_ip, dst_mac) != 0) {
        if (arp_resolve(conn->remote_ip, dst_mac) != 0) {
            uart_printf("[!] TCP: %u.%u.%u.%u のARP解決失敗、送信中止\n",
                        (unsigned)(conn->remote_ip >> 24) & 0xFFu,
                        (unsigned)(conn->remote_ip >> 16) & 0xFFu,
                        (unsigned)(conn->remote_ip >> 8) & 0xFFu,
                        (unsigned)conn->remote_ip & 0xFFu);
            return -1;
        }
    }

    int include_wscale = 0;
    if (flags & TCP_FLAG_SYN) {
        include_wscale = (flags & TCP_FLAG_ACK) ? priv->wscale_enabled : 1;
    }
    uint8_t opt_len = 0;
    if (flags & TCP_FLAG_SYN) {
        opt_len = include_wscale ? 8u : 4u;
    }
    uint16_t hdr_total = (uint16_t)(TCP_HDR_LEN + opt_len);  /* TCPヘッダ+オプション(データ抜き) */
    uint16_t seg_len = (uint16_t)(hdr_total + data_len);      /* IPペイロード全体(ヘッダ+データ) */

    uint8_t src_ip_octets[4];
    uint8_t dst_ip_octets[4];
    ip_to_octets(conn->local_ip, src_ip_octets);
    ip_to_octets(conn->remote_ip, dst_ip_octets);

    if(ts_log_mode()&TS_MODE_HOTPATH) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_send_segment, 0), tcp_conn_arg(conn, data_len));
    unsigned slot = eth_tx_wait_free_slot();
    if(ts_log_mode()&TS_MODE_HOTPATH) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_send_segment, 1), tcp_conn_arg(conn, data_len));
    uint8_t *seg_buf = s_seg_bufs[core][slot];

    ip_build_header(seg_buf, dst_ip_octets, dst_mac, IP_PROTO_TCP, seg_len);

    volatile uint8_t *tcph = seg_buf + IP_PAYLOAD_OFFSET;
    wr16be(tcph + TCP_OFF_SRC_PORT, conn->local_port);
    wr16be(tcph + TCP_OFF_DST_PORT, conn->remote_port);
    wr32be(tcph + TCP_OFF_SEQ, conn->snd_seq);
    wr32be(tcph + TCP_OFF_ACK, (flags & TCP_FLAG_ACK) ? conn->rcv_seq : 0u);
    tcph[TCP_OFF_DATA_OFFSET] = (uint8_t)((hdr_total / 4u) << 4);
    tcph[TCP_OFF_FLAGS] = flags;
    uint32_t ring_capacity_bytes = (uint32_t)net_active_rx_ring_size() * (uint32_t)conn->snd_mss;
    uint32_t safe_window_cap = (ring_capacity_bytes >= TCP_RX_BUF_SIZE)
                                   ? TCP_RX_BUF_SIZE
                                   : (ring_capacity_bytes / 2u);
    uint32_t actual_window = TCP_RX_BUF_SIZE - priv->rx_count;
    if (actual_window > safe_window_cap) actual_window = safe_window_cap;
    uint16_t wire_window;
    if ((flags & TCP_FLAG_SYN) || !priv->wscale_enabled) {
        wire_window = (actual_window > 0xFFFFu) ? 0xFFFFu : (uint16_t)actual_window;
    } else {
        uint32_t scaled = actual_window >> TCP_RCV_WSCALE;
        wire_window = (scaled > 0xFFFFu) ? 0xFFFFu : (uint16_t)scaled;
    }
    wr16be(tcph + TCP_OFF_WINDOW, wire_window);
    wr16be(tcph + TCP_OFF_CHECKSUM, 0);  /* チェックサム計算前に0クリア */
    wr16be(tcph + TCP_OFF_URGENT, 0);
    if (opt_len > 0) {
        tcph[TCP_HDR_LEN + 0] = TCP_OPT_KIND_MSS;
        tcph[TCP_HDR_LEN + 1] = 4;
        wr16be(tcph + TCP_HDR_LEN + 2, net_active_mss_cap());
        if (include_wscale) {
            tcph[TCP_HDR_LEN + 4] = TCP_OPT_KIND_NOP;
            tcph[TCP_HDR_LEN + 5] = TCP_OPT_KIND_WSCALE;
            tcph[TCP_HDR_LEN + 6] = 3;               /* オプション長(kind+len+shiftの3バイト) */
            tcph[TCP_HDR_LEN + 7] = TCP_RCV_WSCALE;  /* shift count */
        }
    }

    uint16_t csum;
    if (net_active_hw_csum_offload()) {
        csum = pseudo_header_checksum_only(src_ip_octets, dst_ip_octets, IP_PROTO_TCP, seg_len);
    } else {
        csum = pseudo_header_checksum2(src_ip_octets, dst_ip_octets, IP_PROTO_TCP,
                                        tcph, hdr_total, data, data_len);
    }
    wr16be(tcph + TCP_OFF_CHECKSUM, csum);

    if(ts_log_mode()&TS_MODE_HOTPATH) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_send_segment, 2), tcp_conn_arg(conn, data_len));

    uint16_t hdr_bytes = (uint16_t)(IP_PAYLOAD_OFFSET + hdr_total);

    if (net_active_tx_zerocopy() && data_len >= 512u) {
        if(ts_log_mode()&TS_MODE_HOTPATH) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_send_segment, 3), tcp_conn_arg(conn, data_len)); // コピー無し(即座)

        dcache_clean_range(seg_buf, hdr_bytes);
        dcache_clean_range((const void *)data, data_len);
        if(ts_log_mode()&TS_MODE_HOTPATH) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_send_segment, 4), tcp_conn_arg(conn, data_len));

        eth_frag_t frags[2];
        frags[0].data = seg_buf;
        frags[0].len  = hdr_bytes;
        frags[1].data = data;
        frags[1].len  = data_len;

        return eth_send_frags_async(frags, 2u);
    }

    const volatile uint8_t *vdata = data;
    volatile_fast_copy((volatile uint8_t *)(seg_buf + hdr_bytes), vdata, data_len);
    if(ts_log_mode()&TS_MODE_HOTPATH) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_send_segment, 5), tcp_conn_arg(conn, data_len));

    eth_frag_t frag;
    frag.data = seg_buf;
    frag.len  = (uint16_t)(hdr_bytes + data_len);

    dcache_clean_range(seg_buf, frag.len);
    if(ts_log_mode()&TS_MODE_HOTPATH) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_send_segment, 6), tcp_conn_arg(conn, data_len));

    return eth_send_frags_async(&frag, 1u);
}

#define TCP_LSO_MAX_DATA_LEN (0xFFFFu - (uint32_t)sizeof(ip_header_t) - (uint32_t)TCP_HDR_LEN)

static int tcp_send_segment_lso(tcp_conn_t *conn, tcp_priv_t *priv,
                                 const void *data, uint32_t data_len)
{
    unsigned core = smp_core_index();

    netif_t *conn_ctx = netif_find_by_ip(conn->local_ip);
    if (conn_ctx) {
        netif_activate(conn_ctx);
    }

    uint8_t dst_mac[ETH_ALEN];
    if (arp_cache_lookup(conn->remote_ip, dst_mac) != 0) {
        if (arp_resolve(conn->remote_ip, dst_mac) != 0) {
            uart_printf("[!] TCP: %u.%u.%u.%u のARP解決失敗、送信中止(LSO)\n",
                        (unsigned)(conn->remote_ip >> 24) & 0xFFu,
                        (unsigned)(conn->remote_ip >> 16) & 0xFFu,
                        (unsigned)(conn->remote_ip >> 8) & 0xFFu,
                        (unsigned)conn->remote_ip & 0xFFu);
            return -1;
        }
    }

    uint32_t seg_len32 = (uint32_t)TCP_HDR_LEN + data_len;
    if (seg_len32 > 0xFFFFu) {
        uart_printf("[!] TCP: LSO data_lenが大きすぎる(%u)、送信中止\n", (unsigned)data_len);
        return -1;
    }
    uint16_t seg_len = (uint16_t)seg_len32;

    uint8_t src_ip_octets[4];
    uint8_t dst_ip_octets[4];
    ip_to_octets(conn->local_ip, src_ip_octets);
    ip_to_octets(conn->remote_ip, dst_ip_octets);

    /* tcp_send_segment()と同じスロット確保規約(コメント参照)。 */
    unsigned slot = eth_tx_wait_free_slot();
    uint8_t *seg_buf = s_seg_bufs[core][slot];

    ip_build_header(seg_buf, dst_ip_octets, dst_mac, IP_PROTO_TCP, seg_len);

    volatile uint8_t *tcph = seg_buf + IP_PAYLOAD_OFFSET;
    wr16be(tcph + TCP_OFF_SRC_PORT, conn->local_port);
    wr16be(tcph + TCP_OFF_DST_PORT, conn->remote_port);
    wr32be(tcph + TCP_OFF_SEQ, conn->snd_seq);
    wr32be(tcph + TCP_OFF_ACK, conn->rcv_seq);
    tcph[TCP_OFF_DATA_OFFSET] = (uint8_t)((TCP_HDR_LEN / 4u) << 4);
    tcph[TCP_OFF_FLAGS] = TCP_FLAG_PSH | TCP_FLAG_ACK;

    uint32_t ring_capacity_bytes = (uint32_t)ETH_RX_RING_SIZE * (uint32_t)conn->snd_mss;
    uint32_t safe_window_cap = ring_capacity_bytes / 2u;
    uint32_t actual_window = TCP_RX_BUF_SIZE - priv->rx_count;
    if (actual_window > safe_window_cap) actual_window = safe_window_cap;
    uint16_t wire_window;
    if (!priv->wscale_enabled) {
        wire_window = (actual_window > 0xFFFFu) ? 0xFFFFu : (uint16_t)actual_window;
    } else {
        uint32_t scaled = actual_window >> TCP_RCV_WSCALE;
        wire_window = (scaled > 0xFFFFu) ? 0xFFFFu : (uint16_t)scaled;
    }
    wr16be(tcph + TCP_OFF_WINDOW, wire_window);
    wr16be(tcph + TCP_OFF_URGENT, 0);

    uint16_t csum = pseudo_header_checksum_only(src_ip_octets, dst_ip_octets, IP_PROTO_TCP, seg_len);
    wr16be(tcph + TCP_OFF_CHECKSUM, csum);

    uint16_t hdr_bytes = (uint16_t)(IP_PAYLOAD_OFFSET + TCP_HDR_LEN);

    dcache_clean_range(seg_buf, hdr_bytes);
    dcache_clean_range((const void *)data, data_len);

    return eth_send_lso_async(seg_buf, hdr_bytes, data, data_len, conn->snd_mss);
}

static void tcp_send_bare_ack(uint32_t local_ip, uint16_t local_port,
                               uint32_t remote_ip, uint16_t remote_port,
                               uint32_t seq, uint32_t ack)
{
    unsigned core = smp_core_index();

    netif_t *conn_ctx = netif_find_by_ip(local_ip);
    if (conn_ctx) {
        netif_activate(conn_ctx);
    }

    uint8_t dst_mac[ETH_ALEN];
    if (arp_cache_lookup(remote_ip, dst_mac) != 0) {
        if (arp_resolve(remote_ip, dst_mac) != 0) {
            return;
        }
    }

    uint8_t src_ip_octets[4], dst_ip_octets[4];
    ip_to_octets(local_ip, src_ip_octets);
    ip_to_octets(remote_ip, dst_ip_octets);

    unsigned slot = eth_tx_wait_free_slot();
    uint8_t *seg_buf = s_seg_bufs[core][slot];

    ip_build_header(seg_buf, dst_ip_octets, dst_mac, IP_PROTO_TCP, TCP_HDR_LEN);

    volatile uint8_t *tcph = seg_buf + IP_PAYLOAD_OFFSET;
    wr16be(tcph + TCP_OFF_SRC_PORT, local_port);
    wr16be(tcph + TCP_OFF_DST_PORT, remote_port);
    wr32be(tcph + TCP_OFF_SEQ, seq);
    wr32be(tcph + TCP_OFF_ACK, ack);
    tcph[TCP_OFF_DATA_OFFSET] = (uint8_t)((TCP_HDR_LEN / 4u) << 4);
    tcph[TCP_OFF_FLAGS] = TCP_FLAG_ACK;
    wr16be(tcph + TCP_OFF_WINDOW, 0);
    wr16be(tcph + TCP_OFF_CHECKSUM, 0);
    wr16be(tcph + TCP_OFF_URGENT, 0);

    uint16_t csum = pseudo_header_checksum2(src_ip_octets, dst_ip_octets, IP_PROTO_TCP,
                                             tcph, TCP_HDR_LEN, NULL, 0);
    wr16be(tcph + TCP_OFF_CHECKSUM, csum);

    eth_frag_t frag;
    frag.data = seg_buf;
    frag.len  = (uint16_t)(IP_PAYLOAD_OFFSET + TCP_HDR_LEN);

    dcache_clean_range(seg_buf, frag.len);
    eth_send_frags_async(&frag, 1u);
}

static volatile int s_abort_requested;

int tcp_abort_requested(void)
{
    return s_abort_requested;
}

void tcp_clear_abort_request(void)
{
    s_abort_requested = 0;
}

static void tcp_cwnd_grow_on_ack(tcp_priv_t *priv, uint16_t mss);

static tcp_async_slot_t *tcp_async_slot_at(tcp_priv_t *priv, unsigned core, unsigned logical_idx);

static void tcp_async_poll(tcp_conn_t *conn, tcp_priv_t *priv)
{
    if (priv->ack_advanced && !priv->in_bulk_send) {
        priv->ack_advanced = 0;
        tcp_cwnd_grow_on_ack(priv, conn->snd_mss);
        if(ts_log_mode()&0x1) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_async_poll, 0), tcp_conn_arg(conn, priv->cwnd));
    }

    while (priv->async_count > 0) {
        tcp_async_slot_t *s = tcp_async_slot_at(priv, conn->owner_core, priv->async_head);
        uint32_t end_seq = s->seq + s->len;
        if (!tcp_seq_lt(priv->snd_una, end_seq)) {
            priv->async_head = (priv->async_head + 1u) % priv->async_cap;
            priv->async_count--;
            if(ts_log_mode()&0x1) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_async_poll, 1), tcp_conn_arg(conn, s->len));
            continue;
        }

        if (!timeout_ms(s->sent_at, s->rto_ms)) {
            return;  /* まだRTO未満、様子見(呼び出し元はブロックしていない) */
        }

        s->retries++;
        if (s->retries > TCP_MAX_RETRIES) {
            uart_printf("[!] TCP: tcp_send_async再送上限到達、ACK確認できず (seq=%u len=%u)\n",
                        s->seq, (unsigned)s->len);
            conn->snd_seq = priv->snd_una;
            priv->async_head  = 0;
            priv->async_count = 0;
            priv->async_short_head  = 0;
            priv->async_short_count = 0;
            return;
        }
        g_tcp_retransmit_count[smp_core_index()]++;
        if(ts_log_mode()&0x1) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_async_poll, 2), tcp_conn_arg(conn, (uint32_t)s->retries));

        uint32_t saved_snd_seq = conn->snd_seq;
        conn->snd_seq = s->seq;
        const uint8_t *rsrc = s->ref ? s->ref : s->buf;
        if (s->len > conn->snd_mss) {
            tcp_send_segment_lso(conn, priv, rsrc, s->len);
        } else {
            tcp_send_segment(conn, priv, TCP_FLAG_PSH | TCP_FLAG_ACK, rsrc, s->len);
        }
        conn->snd_seq = saved_snd_seq;

        s->sent_at = timer_now();
        s->rto_ms *= 2;
        if (s->rto_ms > TCP_MAX_RTO_MS) s->rto_ms = TCP_MAX_RTO_MS;
        return;
    }
}

static void tcp_async_short_poll(tcp_conn_t *conn, tcp_priv_t *priv)
{
    while (priv->async_short_count > 0) {
        tcp_async_short_slot_t *s = &priv->async_short_slots[priv->async_short_head];
        uint32_t end_seq = s->seq + s->len;
        if (!tcp_seq_lt(priv->snd_una, end_seq)) {
            priv->async_short_head = (priv->async_short_head + 1u) % TCP_ASYNC_SHORT_SLOTS;
            priv->async_short_count--;
            if(ts_log_mode()&0x1) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_async_short_poll, 0), tcp_conn_arg(conn, s->len));
            continue;
        }

        if (!timeout_ms(s->sent_at, s->rto_ms)) {
            return;
        }

        s->retries++;
        if (s->retries > TCP_MAX_RETRIES) {
            uart_printf("[!] TCP: tcp_send_async(short)再送上限到達、ACK確認できず (seq=%u len=%u)\n",
                        s->seq, (unsigned)s->len);
            conn->snd_seq = priv->snd_una;
            priv->async_short_head  = 0;
            priv->async_short_count = 0;
            priv->async_head  = 0;
            priv->async_count = 0;
            return;
        }
        g_tcp_retransmit_count[smp_core_index()]++;
        if(ts_log_mode()&0x1) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_async_short_poll, 1), tcp_conn_arg(conn, (uint32_t)s->retries));

        uint32_t saved_snd_seq = conn->snd_seq;
        conn->snd_seq = s->seq;
        tcp_send_segment(conn, priv, TCP_FLAG_PSH | TCP_FLAG_ACK, s->buf, s->len);
        conn->snd_seq = saved_snd_seq;

        s->sent_at = timer_now();
        s->rto_ms *= 2;
        if (s->rto_ms > TCP_MAX_RTO_MS) s->rto_ms = TCP_MAX_RTO_MS;
        return;
    }
}

static void tcp_poll_once_ex(int check_ctrl_c)
{
    unsigned core = smp_core_index();

    if (check_ctrl_c && uart_check_ctrl_c()) {
        s_abort_requested = 1;
    }

    net_poll_all_and_dispatch();

    for (unsigned i = 0; i < TCP_MAX_CONNS; i++) {
        if (s_conns[core][i] != NULL) {
            tcp_async_poll(s_conns[core][i], &s_priv[core][i]);
            tcp_async_short_poll(s_conns[core][i], &s_priv[core][i]);
        }
    }

    tcp_timewait_reap();
}

static void tcp_poll_once(void)
{
    tcp_poll_once_ex(1);
}

static int tcp_send_reliable(tcp_conn_t *conn, tcp_priv_t *priv, uint8_t flags,
                              const void *data, uint16_t data_len,
                              uint32_t expected_ack)
{
    priv->expected_ack = expected_ack;
    priv->ack_received = 0;

    uint32_t rto_ms = priv->rto_ms;
    for (int attempt = 0; attempt <= TCP_MAX_RETRIES; attempt++) {
        if (attempt > 0) {
            g_tcp_retransmit_count[smp_core_index()]++;
            uart_printf("[TCP] 再送 (%d/%d, RTO=%ums)\n", attempt, TCP_MAX_RETRIES, rto_ms);
        }
        uint64_t sent_at = timer_now();
        if (tcp_send_segment(conn, priv, flags, data, data_len) != 0) {
            return -1;  /* 送信自体の失敗(ARP解決失敗等)は再送しても無駄 */
        }

        do {
            tcp_poll_once();
            if (tcp_abort_requested()) {
                return -1;  /* Ctrl+C中断(tcp.hのtcp_abort_requested()参照) */
            }
            if (priv->ack_received) {
                if (attempt == 0) {
                    tcp_rtt_update(priv, timer_now() - sent_at);
                }
                return 0;
            }
            if (conn->state == TCP_TIME_WAIT) {
                return 0;
            }
            if (conn->state == TCP_CLOSED) {
                return -1;  /* RST等でコネクションが失われた */
            }
        } while (!timeout_ms(sent_at, rto_ms));

        rto_ms *= 2;
        if (rto_ms > TCP_MAX_RTO_MS) rto_ms = TCP_MAX_RTO_MS;
    }

    uart_printf("[!] TCP: 再送上限到達、ACK確認できず\n");
    return -1;
}

static void tcp_parse_syn_options(tcp_conn_t *conn, tcp_priv_t *priv,
                                   const volatile uint8_t *opts, uint8_t opts_len)
{
    uint8_t i = 0;
    while (i < opts_len) {
        uint8_t kind = opts[i];
        if (kind == TCP_OPT_KIND_END) {
            break;
        }
        if (kind == TCP_OPT_KIND_NOP) {
            i++;
            continue;
        }
        if ((uint8_t)(i + 1) >= opts_len) {
            break;  /* 長さバイトが読めない、壊れたオプション列 */
        }
        uint8_t opt_len = opts[i + 1];
        if (opt_len < 2 || (uint8_t)(i + opt_len) > opts_len) {
            break;  /* 不正な長さ */
        }
        if (kind == TCP_OPT_KIND_MSS && opt_len == 4) {
            uint16_t peer_mss = rd16be(opts + i + 2);
            uint16_t local_cap = net_active_mss_cap();
            if (peer_mss > local_cap) peer_mss = local_cap;
            conn->snd_mss = peer_mss;
            uart_printf("[TCP] 相手のMSSオプション受信: %u (採用値=%u)\n",
                        rd16be(opts + i + 2), conn->snd_mss);
        } else if (kind == TCP_OPT_KIND_WSCALE && opt_len == 3) {
            uint8_t peer_shift = opts[i + 2];
            if (peer_shift > 14u) peer_shift = 14u;
            priv->wscale_enabled = 1;
            priv->snd_wscale = peer_shift;
            uart_printf("[TCP] 相手のWindow Scaleオプション受信: shift=%u\n", peer_shift);
        }
        i = (uint8_t)(i + opt_len);
    }
}

typedef tcp_async_slot_t tcp_async_mlx5_extra_t[TCP_ASYNC_SLOTS_MLX5_EXTRA];
static tcp_async_mlx5_extra_t s_async_mlx5_overflow[SMP_MAX_CORES][TCP_ASYNC_MLX5_OVERFLOW_CONNS];
static uint8_t s_async_mlx5_overflow_used[SMP_MAX_CORES][TCP_ASYNC_MLX5_OVERFLOW_CONNS];

static void tcp_async_overflow_release(unsigned core, int idx)
{
    if (idx >= 0 && (unsigned)idx < TCP_ASYNC_MLX5_OVERFLOW_CONNS) {
        s_async_mlx5_overflow_used[core][idx] = 0u;
    }
}

static int tcp_async_overflow_acquire(unsigned core)
{
    for (unsigned i = 0; i < TCP_ASYNC_MLX5_OVERFLOW_CONNS; i++) {
        if (!s_async_mlx5_overflow_used[core][i]) {
            s_async_mlx5_overflow_used[core][i] = 1u;
            return (int)i;
        }
    }
    return -1;  /* プール枯渇 -- 呼び出し元はTCP_ASYNC_SLOTS基礎値のままフォールバックする */
}

static tcp_async_slot_t *tcp_async_slot_at(tcp_priv_t *priv, unsigned core, unsigned logical_idx)
{
    if (logical_idx < TCP_ASYNC_SLOTS) {
        return &priv->async_slots[logical_idx];
    }
    unsigned extra_idx = logical_idx - TCP_ASYNC_SLOTS;
    if (priv->async_overflow_idx >= 0 && extra_idx < TCP_ASYNC_SLOTS_MLX5_EXTRA) {
        return &s_async_mlx5_overflow[core][priv->async_overflow_idx][extra_idx];
    }
    return NULL;  /* async_cap管理が正しければ到達しないはず */
}

static void tcp_priv_try_grant_mlx5_async_overflow(tcp_priv_t *priv, unsigned core, uint32_t local_ip)
{
    netif_t *ctx = netif_find_by_ip(local_ip);
    if (!ctx || !ctx->hw_csum_offload) {
        return;  /* RP1、または未解決 -- TCP_ASYNC_SLOTSのまま */
    }
    int idx = tcp_async_overflow_acquire(core);
    if (idx >= 0) {
        priv->async_overflow_idx = idx;
        priv->async_cap = TCP_ASYNC_SLOTS + TCP_ASYNC_SLOTS_MLX5_EXTRA;
    }
}

static void tcp_priv_init(tcp_priv_t *priv, unsigned core)
{
    if (priv->async_overflow_ever_init) {
        tcp_async_overflow_release(core, priv->async_overflow_idx);
    }
    priv->async_overflow_ever_init = 1u;
    priv->async_overflow_idx = -1;
    priv->async_cap = TCP_ASYNC_SLOTS;

    priv->ack_received  = 0;
    priv->expected_ack  = 0;
    priv->snd_una       = 0;
    priv->ack_advanced  = 0;
    priv->srtt_us       = 0;
    priv->rttvar_us     = 0;
    priv->rto_ms        = TCP_INITIAL_RTO_MS;
    priv->cwnd          = 0;
    priv->ssthresh      = 0xFFFFFFFFu;
    priv->rx_read       = 0;
    priv->rx_count      = 0;
    priv->fin_received  = 0;
    priv->recv_upcall     = NULL;
    priv->recv_upcall_ctx = NULL;
    priv->wscale_enabled = 0;
    priv->snd_wscale     = 0;
    priv->unacked_full_segments = 0;
    priv->unacked_consumed_bytes = 0;
    for (unsigned i = 0; i < TCP_OOO_SLOTS; i++) {
        priv->ooo[i].valid = 0;
    }
    priv->async_head  = 0;
    priv->async_count = 0;
    priv->async_short_head  = 0;
    priv->async_short_count = 0;
    priv->in_bulk_send = 0;
    priv->connect_attempt = 0;
    priv->connect_rto_ms  = TCP_INITIAL_RTO_MS;
    priv->connect_sent_at = 0;
}

static void tcp_cwnd_init(tcp_conn_t *conn, tcp_priv_t *priv)
{
    uint32_t four_mss  = 4u * conn->snd_mss;
    uint32_t two_mss   = 2u * conn->snd_mss;
    uint32_t floor_val = (two_mss > 4380u) ? two_mss : 4380u;
    priv->cwnd = (four_mss < floor_val) ? four_mss : floor_val;
    priv->ssthresh = 0xFFFFFFFFu;  /* 初回はロスがあるまで実質無制限(スロースタート主導) */
}

void tcp_connect_begin(tcp_conn_t *conn, uint32_t dst_ip, uint16_t dst_port)
{
    unsigned core = smp_core_index();
    int slot = tcp_find_free_slot();
    if (slot < 0) {
        uart_printf("[!] TCP: 空きコネクションスロットが無い(最大%u本)\n", TCP_MAX_CONNS);
        conn->state = TCP_CLOSED;
        return;
    }
    tcp_priv_t *priv = &s_priv[core][slot];

    conn->state       = TCP_CLOSED;
    conn->local_ip    = NET_SELF_IP;
    conn->remote_ip   = dst_ip;
    conn->remote_port = dst_port;
    conn->snd_win     = 0;                     /* 相手の最初のACKで確定するまでは未知 */
    conn->snd_mss     = TCP_MSS_DEFAULT_RFC879; /* 相手がMSSオプションを付けなければこの既定値のまま */
    conn->rcv_seq     = 0;

    uint32_t isn = (uint32_t)timer_now();
    conn->snd_seq   = isn;
    conn->local_port = (uint16_t)(49152u + (isn & 0x3fffu));

    tcp_priv_init(priv, core);
    tcp_priv_try_grant_mlx5_async_overflow(priv, core, conn->local_ip);

    conn->owner_core = core;
    s_conns[core][slot] = conn;

    uint8_t dst_octets[4];
    ip_to_octets(dst_ip, dst_octets);
    uart_printf("[TCP] connect: %u.%u.%u.%u:%u へSYN送信 (local_port=%u, isn=%u, slot=%d)\n",
                dst_octets[0], dst_octets[1], dst_octets[2], dst_octets[3],
                dst_port, conn->local_port, isn, slot);

    conn->state = TCP_SYN_SENT;
    priv->expected_ack    = isn + 1;
    priv->ack_received     = 0;
    priv->connect_attempt  = 0;
    priv->connect_rto_ms   = priv->rto_ms;  /* tcp_priv_init()直後はTCP_INITIAL_RTO_MS */
    priv->connect_sent_at  = timer_now();

    if (tcp_send_segment(conn, priv, TCP_FLAG_SYN, NULL, 0) != 0) {
        uart_printf("[!] TCP: SYN送信失敗\n");
        conn->state = TCP_CLOSED;
        s_conns[core][slot] = NULL;
    }
}

int tcp_connect_poll(tcp_conn_t *conn)
{
    tcp_priv_t *priv = tcp_priv_for(conn);
    if (!priv) {
        return -1;  /* tcp_connect_begin()を呼んでいない(呼び出し規約違反) */
    }

    if (tcp_abort_requested()) {
        conn->state = TCP_CLOSED;
        unsigned slot = tcp_conn_slot(conn);
        if (slot < TCP_MAX_CONNS) s_conns[conn->owner_core][slot] = NULL;
        return -1;
    }

    if (priv->ack_received) {
        if (conn->state == TCP_ESTABLISHED) {
            if (priv->connect_attempt == 0) {
                tcp_rtt_update(priv, timer_now() - priv->connect_sent_at);
            }
            conn->snd_seq = priv->expected_ack;  /* SYNは1バイト分のシーケンス番号を消費する */
            tcp_cwnd_init(conn, priv);
            uart_printf("[TCP] connect: ESTABLISHED (peer MSS=%u, 初期cwnd=%u)\n",
                        conn->snd_mss, priv->cwnd);
            return 1;
        }
    }

    if (conn->state == TCP_CLOSED) {
        /* RST等でtcp_input()がstateを落としたケース。 */
        uart_printf("[!] TCP: connect失敗 (state=%d)\n", (int)conn->state);
        unsigned slot = tcp_conn_slot(conn);
        if (slot < TCP_MAX_CONNS) s_conns[conn->owner_core][slot] = NULL;
        return -1;
    }

    if (!timeout_ms(priv->connect_sent_at, priv->connect_rto_ms)) {
        return 0;  /* まだ待つ */
    }

    /* RTOタイムアウト -- 再送するか、再送上限なら諦める。 */
    priv->connect_attempt++;
    if (priv->connect_attempt > TCP_MAX_RETRIES) {
        uart_printf("[!] TCP: SYN送信/再送すべて失敗\n");
        conn->state = TCP_CLOSED;
        unsigned slot = tcp_conn_slot(conn);
        if (slot < TCP_MAX_CONNS) s_conns[conn->owner_core][slot] = NULL;
        return -1;
    }

    g_tcp_retransmit_count[smp_core_index()]++;
    uart_printf("[TCP] 再送 (%u/%d, RTO=%ums)\n",
                priv->connect_attempt, TCP_MAX_RETRIES, priv->connect_rto_ms);
    priv->connect_rto_ms *= 2;
    if (priv->connect_rto_ms > TCP_MAX_RTO_MS) priv->connect_rto_ms = TCP_MAX_RTO_MS;
    priv->connect_sent_at = timer_now();

    if (tcp_send_segment(conn, priv, TCP_FLAG_SYN, NULL, 0) != 0) {
        conn->state = TCP_CLOSED;
        unsigned slot = tcp_conn_slot(conn);
        if (slot < TCP_MAX_CONNS) s_conns[conn->owner_core][slot] = NULL;
        return -1;
    }
    return 0;
}

static void tcp_cwnd_grow_on_ack(tcp_priv_t *priv, uint16_t mss)
{
    if (priv->cwnd < priv->ssthresh) {
        priv->cwnd += mss;
    } else {
        uint32_t inc = ((uint32_t)mss * mss) / priv->cwnd;
        if (inc == 0) inc = 1u;
        priv->cwnd += inc;
    }
}

int tcp_send(tcp_conn_t *conn, const void *buf, uint32_t len)
{
    if (conn->state != TCP_ESTABLISHED && conn->state != TCP_CLOSE_WAIT) {
        uart_printf("[!] tcp_send: ESTABLISHED/CLOSE_WAITでない (state=%d)\n", (int)conn->state);
        return -1;
    }
    if (len == 0) {
        return 0;
    }

    tcp_priv_t *priv = tcp_priv_for(conn);
    if (!priv) {
        uart_printf("[!] tcp_send: 未登録のconn(tcp_connect()を呼んでいない)\n");
        return -1;
    }

    const uint8_t *data = buf;

    if(ts_log_mode()&0x1) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_send, 0), tcp_conn_arg(conn, len));

    uint32_t base_seq = conn->snd_seq;
    uint32_t end_seq   = base_seq + len;
    uint32_t snd_nxt    = base_seq;   /* 次に新規送信するseq */

    priv->snd_una = base_seq;
    priv->ack_advanced = 0;

    priv->in_bulk_send = 1;

    uint64_t overall_start = timer_now();

    uint32_t last_logged_swin = 0xFFFFFFFFu;

    int      rto_active = 0;            /* 未確認データがあり再送タイマが有効か */
    uint64_t window_sent_at = 0;        /* 現在の未確認ウィンドウの先頭を送った時刻(RTT計測用) */
    uint32_t rto_ms = priv->rto_ms;
    int      window_retransmitted = 0;  /* 現在の未確認ウィンドウ内で再送が起きたか(Karnのアルゴリズム) */
    int      retransmit_attempts = 0;   /* 連続再送回数(進捗があるたびリセット) */

    while (tcp_seq_lt(priv->snd_una, end_seq)) {
        if (timeout_ms(overall_start, TCP_SEND_OVERALL_TIMEOUT_MS)) {
            uart_printf("[!] TCP: tcp_send全体タイムアウト (%u/%u バイト送信済み)\n",
                        (unsigned)(priv->snd_una - base_seq), len);
            break;
        }
        if (conn->state != TCP_ESTABLISHED && conn->state != TCP_CLOSE_WAIT) {
            uart_printf("[!] TCP: 送信中にESTABLISHED/CLOSE_WAITでなくなった (state=%d)\n",
                        (int)conn->state);
            break;
        }
        if (tcp_abort_requested()) {
            /* Ctrl+C中断(tcp.hのtcp_abort_requested()参照)。 */
            uart_printf("[TCP] Ctrl+Cで送信を中断 (%u/%u バイト送信済み)\n",
                        (unsigned)(priv->snd_una - base_seq), len);
            break;
        }

        uint32_t usable_window = conn->snd_win;
        if (priv->cwnd < usable_window) usable_window = priv->cwnd;
        if (usable_window == 0) usable_window = 1u;

        if (tcp_seq_lt(snd_nxt, end_seq) && !tcp_seq_lt(snd_nxt, priv->snd_una + usable_window)) {
            if (usable_window != last_logged_swin) {
                if(ts_log_mode()&0x1) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_send, 1), tcp_conn_arg(conn, usable_window));
                last_logged_swin = usable_window;
            }
        }

        while (tcp_seq_lt(snd_nxt, end_seq) &&
               tcp_seq_lt(snd_nxt, priv->snd_una + usable_window)) {
            uint32_t remaining_in_window = (priv->snd_una + usable_window) - snd_nxt;
            uint32_t remaining_data = end_seq - snd_nxt;
            uint32_t chunk32 = (remaining_in_window < remaining_data) ? remaining_in_window : remaining_data;
            uint32_t lso_max = net_active_lso_max_bytes();
            if (lso_max > TCP_LSO_MAX_DATA_LEN) lso_max = TCP_LSO_MAX_DATA_LEN;
            uint32_t seg_cap = (lso_max > 0u) ? lso_max : conn->snd_mss;
            if (chunk32 > seg_cap) chunk32 = seg_cap;
            if (chunk32 == 0) break;
            uint16_t chunk = (uint16_t)chunk32; // TCP_LSO_MAX_DATA_LEN/snd_mssいずれもuint16_tへ安全に収まる

            conn->snd_seq = snd_nxt;  /* tcp_send_segment()/tcp_send_segment_lso()共通、conn->snd_seqをSEQフィールドに使う */
            int seg_send_rc = (lso_max > 0u && chunk32 > conn->snd_mss)
                ? tcp_send_segment_lso(conn, priv, data + (snd_nxt - base_seq), chunk32)
                : tcp_send_segment(conn, priv, TCP_FLAG_PSH | TCP_FLAG_ACK,
                                    data + (snd_nxt - base_seq), chunk);
            if (seg_send_rc != 0) {
                break;
            }
            if(ts_log_mode()&0x1) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_send, 2), tcp_conn_arg(conn, chunk));
            snd_nxt += chunk;

            if (!rto_active) {
                rto_active = 1;
                window_sent_at = timer_now();
                window_retransmitted = 0;
            }

            tcp_poll_once();
            if (tcp_abort_requested()) {
                break;
            }
        }

        tcp_poll_once();

        if (priv->ack_advanced) {
            priv->ack_advanced = 0;
            retransmit_attempts = 0;  /* 進捗があったので連続再送カウントをリセット */

            if (!window_retransmitted) {
                tcp_rtt_update(priv, timer_now() - window_sent_at);
            }

            tcp_cwnd_grow_on_ack(priv, conn->snd_mss);

            if(ts_log_mode()&0x1) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_send, 3), tcp_conn_arg(conn, priv->cwnd));

            if (tcp_seq_lt(priv->snd_una, snd_nxt)) {
                rto_active = 1;
                window_sent_at = timer_now();
            } else {
                rto_active = 0;
            }
            rto_ms = priv->rto_ms;
        }

        if (rto_active && timeout_ms(window_sent_at, rto_ms)) {
            retransmit_attempts++;
            if (retransmit_attempts > TCP_MAX_RETRIES) {
                uart_printf("[!] TCP: 再送上限到達、送信を諦める (%u/%u バイト送信済み)\n",
                            (unsigned)(priv->snd_una - base_seq), len);
                break;
            }
            g_tcp_retransmit_count[smp_core_index()]++;
            uart_printf("[TCP] 送信ウィンドウ再送 (%d/%d, una=%u nxt=%u RTO=%ums)\n",
                        retransmit_attempts, TCP_MAX_RETRIES, priv->snd_una, snd_nxt, rto_ms);
            if(ts_log_mode()&0x1) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_send, 4), tcp_conn_arg(conn, (uint32_t)retransmit_attempts));

            uint32_t flight = snd_nxt - priv->snd_una;
            uint32_t half = flight / 2u;
            priv->ssthresh = (half > 2u * conn->snd_mss) ? half : 2u * conn->snd_mss;
            priv->cwnd = conn->snd_mss;

            rto_ms *= 2;
            if (rto_ms > TCP_MAX_RTO_MS) rto_ms = TCP_MAX_RTO_MS;

            uint32_t resend_seq = priv->snd_una;
            while (tcp_seq_lt(resend_seq, snd_nxt)) {
                uint32_t remain = snd_nxt - resend_seq;
                uint16_t rchunk = (uint16_t)((remain > conn->snd_mss) ? conn->snd_mss : remain);
                conn->snd_seq = resend_seq;
                if (tcp_send_segment(conn, priv, TCP_FLAG_PSH | TCP_FLAG_ACK,
                                      data + (resend_seq - base_seq), rchunk) != 0) {
                    break;
                }
                /* TCP層の性能分析用: Go-Back-Nで実際に再送されたバイト数。 */
                if(ts_log_mode()&0x1) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_send, 5), tcp_conn_arg(conn, rchunk));
                resend_seq += rchunk;
            }
            window_sent_at = timer_now();
            window_retransmitted = 1;
        }
    }

    conn->snd_seq = priv->snd_una;  /* 実際に確認された分だけ進める */
    uint32_t sent_total = priv->snd_una - base_seq;
    if(ts_log_mode()&0x1) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_send, 6), tcp_conn_arg(conn, sent_total));
    priv->in_bulk_send = 0;
    return sent_total > 0 ? (int)sent_total : -1;
}

static void tcp_async_flush_until_room(tcp_conn_t *conn, tcp_priv_t *priv)
{
    (void)conn;
    while (priv->async_count >= priv->async_cap) {
        tcp_poll_once();
        if (tcp_abort_requested()) {
            /* Ctrl+C中断、追跡を打ち切る。 */
            priv->async_head  = 0;
            priv->async_count = 0;
            break;
        }
    }
}

static int tcp_send_async_enqueue(tcp_conn_t *conn, tcp_priv_t *priv,
                                   const void *buf, uint16_t len, int use_lso,
                                   int is_ref)
{
    uint32_t seq = conn->snd_seq;

    if(ts_log_mode()&0x1) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_send_async_enqueue, 0), tcp_conn_arg(conn, len));

    int rc = use_lso
        ? tcp_send_segment_lso(conn, priv, buf, len)
        : tcp_send_segment(conn, priv, TCP_FLAG_PSH | TCP_FLAG_ACK, buf, len);
    if (rc != 0) {
        return -1;
    }

    unsigned slot_idx = (priv->async_head + priv->async_count) % priv->async_cap;
    tcp_async_slot_t *slot = tcp_async_slot_at(priv, conn->owner_core, slot_idx);

    if (is_ref) {
        slot->ref = (const uint8_t *)buf;
    } else {
        volatile_fast_copy(slot->buf, buf, len);
        slot->ref = 0;
    }
    slot->seq     = seq;
    slot->len     = len;
    slot->sent_at = timer_now();
    slot->rto_ms  = priv->rto_ms;
    slot->retries = 0;
    priv->async_count++;

    conn->snd_seq = seq + len;  /* ACKを待たず楽観的に進める */
    return 0;
}

static int tcp_send_async_short(tcp_conn_t *conn, tcp_priv_t *priv, const void *buf, uint16_t len)
{
    while (priv->async_short_count >= TCP_ASYNC_SHORT_SLOTS) {
        tcp_poll_once();
        if (tcp_abort_requested()) {
            priv->async_short_head  = 0;
            priv->async_short_count = 0;
            return -1;
        }
    }

    uint32_t outstanding   = conn->snd_seq - priv->snd_una;
    uint32_t usable_window = conn->snd_win;
    if (priv->cwnd < usable_window) usable_window = priv->cwnd;
    if (usable_window == 0) usable_window = 1u;
    while (usable_window <= outstanding) {
        tcp_poll_once();
        if (tcp_abort_requested() ||
            (conn->state != TCP_ESTABLISHED && conn->state != TCP_CLOSE_WAIT)) {
            return -1;
        }
        outstanding   = conn->snd_seq - priv->snd_una;
        usable_window = conn->snd_win;
        if (priv->cwnd < usable_window) usable_window = priv->cwnd;
        if (usable_window == 0) usable_window = 1u;
    }

    uint32_t seq = conn->snd_seq;
    if(ts_log_mode()&0x1) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_send_async_short, 0), tcp_conn_arg(conn, len));

    if (tcp_send_segment(conn, priv, TCP_FLAG_PSH | TCP_FLAG_ACK, buf, len) != 0) {
        return -1;
    }

    unsigned slot_idx = (priv->async_short_head + priv->async_short_count) % TCP_ASYNC_SHORT_SLOTS;
    tcp_async_short_slot_t *slot = &priv->async_short_slots[slot_idx];
    volatile_fast_copy(slot->buf, buf, len);
    slot->seq     = seq;
    slot->len     = len;
    slot->sent_at = timer_now();
    slot->rto_ms  = priv->rto_ms;
    slot->retries = 0;
    priv->async_short_count++;

    conn->snd_seq = seq + len;
    return (int)len;
}

static int tcp_send_async_ex(tcp_conn_t *conn, const void *buf, uint16_t len, int is_ref)
{
    if (conn->state != TCP_ESTABLISHED && conn->state != TCP_CLOSE_WAIT) {
        uart_printf("[!] tcp_send_async: ESTABLISHED/CLOSE_WAITでない (state=%d)\n", (int)conn->state);
        return -1;
    }
    if (len == 0) {
        return 0;
    }

    tcp_priv_t *priv = tcp_priv_for(conn);
    if (!priv) {
        uart_printf("[!] tcp_send_async: 未登録のconn(tcp_connect()を呼んでいない)\n");
        return -1;
    }

    if (!is_ref && len <= TCP_ASYNC_SHORT_MAX_LEN) {
        return tcp_send_async_short(conn, priv, buf, len);
    }

    if (len > TCP_ASYNC_MAX_LEN) {
        return tcp_send(conn, buf, len);
    }

    netif_t *conn_ctx = netif_find_by_ip(conn->local_ip);
    uint32_t lso_cap = conn_ctx ? conn_ctx->hw_lso_max_bytes : 0u;
    if (lso_cap > TCP_ASYNC_MAX_LEN) lso_cap = TCP_ASYNC_MAX_LEN;

    uint32_t sent_total = 0;
    const uint8_t *src = (const uint8_t *)buf;

    while (sent_total < (uint32_t)len) {
        if (priv->async_count >= priv->async_cap) {
            /* キュー満杯 -- 最低1件空くまで待ってから続ける。 */
            tcp_async_flush_until_room(conn, priv);
        }

        uint32_t outstanding = conn->snd_seq - priv->snd_una;
        uint32_t usable_window = conn->snd_win;
        if (priv->cwnd < usable_window) usable_window = priv->cwnd;
        if (usable_window == 0) usable_window = 1u;
        uint32_t room = (usable_window > outstanding) ? (usable_window - outstanding) : 0u;
        while (room == 0) {
            tcp_poll_once();
            if (tcp_abort_requested() ||
                (conn->state != TCP_ESTABLISHED && conn->state != TCP_CLOSE_WAIT)) {
                return (sent_total > 0) ? (int)sent_total : -1;
            }
            outstanding = conn->snd_seq - priv->snd_una;
            usable_window = conn->snd_win;
            if (priv->cwnd < usable_window) usable_window = priv->cwnd;
            if (usable_window == 0) usable_window = 1u;
            room = (usable_window > outstanding) ? (usable_window - outstanding) : 0u;
        }

        uint32_t remaining = (uint32_t)len - sent_total;
        uint32_t max_chunk = (lso_cap > conn->snd_mss) ? lso_cap : (uint32_t)conn->snd_mss;
        uint32_t chunk32 = (remaining < max_chunk) ? remaining : max_chunk;
        if (chunk32 > room) chunk32 = room;
        int use_lso = (lso_cap > conn->snd_mss) && (chunk32 > conn->snd_mss);
        uint16_t chunk = (uint16_t)chunk32;

        if (tcp_send_async_enqueue(conn, priv, src + sent_total, chunk, use_lso, is_ref) != 0) {
            return (sent_total > 0) ? (int)sent_total : -1;
        }
        sent_total += chunk;
    }

    return (int)sent_total;
}

int tcp_send_async(tcp_conn_t *conn, const void *buf, uint16_t len)
{
    return tcp_send_async_ex(conn, buf, len, 0);
}

int tcp_send_async_ref(tcp_conn_t *conn, const void *buf, uint16_t len)
{
    return tcp_send_async_ex(conn, buf, len, 1);
}

static int tcp_recv_internal(tcp_conn_t *conn, void *buf, uint32_t maxlen, uint32_t timeout_val_ms, int send_ack)
{
    tcp_priv_t *priv = tcp_priv_for(conn);
    if (!priv) {
        uart_printf("[!] tcp_recv: 未登録のconn(tcp_connect()を呼んでいない)\n");
        return -1;
    }

    volatile uint8_t *vout = buf;

    int log_idle_poll = (timeout_val_ms != 0);
    if (log_idle_poll) {
        if(ts_log_mode()&0x1) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_recv_internal, 0), tcp_conn_arg(conn, maxlen));
    }

    uint64_t start = timer_now();
    int check_ctrl_c = (timeout_val_ms != 0);
    do {
        tcp_poll_once_ex(check_ctrl_c);

        if (check_ctrl_c && tcp_abort_requested()) {
            if(ts_log_mode()&0x1) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_recv_internal, 1), tcp_conn_arg(conn, 0x00FFFFFEu));
            return -1;
        }

        if (priv->rx_count > 0) {
            uint32_t n = priv->rx_count;
            if (n > maxlen) n = maxlen;
            uint64_t cpt0 = timer_now();
            uint32_t first_len = TCP_RX_BUF_SIZE - priv->rx_read;
            if (first_len > n) first_len = n;
            volatile_fast_copy(vout, &priv->rx_buf[priv->rx_read], first_len);
            if (first_len < n) {
                volatile_fast_copy(vout + first_len, &priv->rx_buf[0], n - first_len);
            }
            g_tcp_copy3_ns    += get_ns_from(cpt0);
            g_tcp_copy3_bytes += n;
            priv->rx_read = (priv->rx_read + n) % TCP_RX_BUF_SIZE;
            priv->rx_count = priv->rx_count - n;

            if (send_ack && (conn->state == TCP_ESTABLISHED || conn->state == TCP_CLOSE_WAIT)) {
                tcp_send_segment(conn, priv, TCP_FLAG_ACK, NULL, 0);
            } else if (!send_ack && (conn->state == TCP_ESTABLISHED || conn->state == TCP_CLOSE_WAIT)) {
                priv->unacked_consumed_bytes += n;
                uint32_t threshold = (uint32_t)conn->snd_mss * TCP_RECV_NOACK_ACK_THRESHOLD_MSS;
                if (threshold == 0) threshold = TCP_RECV_NOACK_ACK_THRESHOLD_MSS * 536u;
                if (priv->unacked_consumed_bytes >= threshold) {
                    TS_HOT(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_recv_internal, 2), tcp_conn_arg(conn, priv->unacked_consumed_bytes));
                    tcp_send_segment(conn, priv, TCP_FLAG_ACK, NULL, 0);
                    priv->unacked_consumed_bytes = 0;
                }
            }
            if(ts_log_mode()&0x1) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_recv_internal, 3), tcp_conn_arg(conn, n));
            return (int)n;
        }
        if (priv->fin_received) {
            priv->fin_received = 0;
            if(ts_log_mode()&0x1) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_recv_internal, 4), tcp_conn_arg(conn, 0u));
            return 0;  /* 相手がFINを送りコネクションを閉じた */
        }
    } while (!timeout_ms(start, timeout_val_ms));

    if (log_idle_poll) {
        if(ts_log_mode()&0x1) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_recv_internal, 5), tcp_conn_arg(conn, 0x00FFFFFFu));  /* タイムアウト */
    }
    return -1;  /* タイムアウト */
}

int tcp_recv(tcp_conn_t *conn, void *buf, uint32_t maxlen, uint32_t timeout_ms)
{
    return tcp_recv_internal(conn, buf, maxlen, timeout_ms, 1);
}

int tcp_recv_no_ack(tcp_conn_t *conn, void *buf, uint32_t maxlen, uint32_t timeout_ms)
{
    return tcp_recv_internal(conn, buf, maxlen, timeout_ms, 0);
}

void tcp_close(tcp_conn_t *conn)
{
    tcp_priv_t *priv = tcp_priv_for(conn);
    if (!priv) {
        conn->state = TCP_CLOSED;
        return;  /* 未登録(既にclose済み等) */
    }

    if (conn->state == TCP_ESTABLISHED || conn->state == TCP_CLOSE_WAIT) {
        int active = (conn->state == TCP_ESTABLISHED);
        uart_printf("[TCP] close: FIN送信 (%s)\n", active ? "能動close" : "受動close完了");
        uint32_t fin_seq = conn->snd_seq;
        conn->state = active ? TCP_FIN_WAIT_1 : TCP_LAST_ACK;

        if (tcp_send_reliable(conn, priv, TCP_FLAG_FIN | TCP_FLAG_ACK, NULL, 0, fin_seq + 1) == 0) {
            conn->snd_seq = fin_seq + 1;  /* FINは1バイト分のシーケンス番号を消費する */

            if (active) {
                uint64_t start = timer_now();
                while (conn->state != TCP_TIME_WAIT && conn->state != TCP_CLOSED &&
                       !timeout_ms(start, TCP_CLOSE_FIN_WAIT_MS)) {
                    tcp_poll_once();
                }
                if (conn->state != TCP_TIME_WAIT && conn->state != TCP_CLOSED) {
                    tcp_timewait_register(conn->local_ip, conn->local_port,
                                           conn->remote_ip, conn->remote_port,
                                           conn->snd_seq);
                }
            }
        } else {
            uart_printf("[!] TCP: FIN再送上限到達、ローカルで強制クローズ\n");
        }
    }

    conn->state = TCP_CLOSED;
    {
        unsigned core = conn->owner_core;
        for (unsigned i = 0; i < TCP_MAX_CONNS; i++) {
            if (s_conns[core][i] == conn) {
                s_conns[core][i] = NULL;
                break;
            }
        }
    }
}

int tcp_listen(uint16_t port, netif_t *ctx)
{
    smp_spin_lock(&s_listener_lock);
    for (unsigned i = 0; i < TCP_LISTENER_TOTAL; i++) {
        if (!s_listeners[i].in_use) {
            s_listeners[i].in_use       = 1;
            s_listeners[i].port         = port;
            s_listeners[i].bound_ctx    = ctx;
            s_listeners[i].accept_conn  = NULL;
            s_listeners[i].accept_ready = 0;
            smp_spin_unlock(&s_listener_lock);
            return (int)i;
        }
    }
    smp_spin_unlock(&s_listener_lock);
    return -1;
}

void tcp_unlisten(int listener)
{
    smp_spin_lock(&s_listener_lock);
    tcp_listener_slot_t *l = tcp_listener_for(listener);
    if (l) {
        l->in_use       = 0;
        l->accept_conn  = NULL;
        l->accept_ready = 0;
    }
    smp_spin_unlock(&s_listener_lock);
}

int tcp_window_scaling_enabled(const tcp_conn_t *conn)
{
    tcp_priv_t *priv = tcp_priv_for((tcp_conn_t *)conn);
    return priv ? priv->wscale_enabled : 0;
}

void tcp_debug_dump_rx(const tcp_conn_t *conn)
{
    tcp_priv_t *priv = tcp_priv_for((tcp_conn_t *)conn);
    if (!priv) {
        uart_printf("[DEBUG] tcp_debug_dump_rx: 未登録のconn\n");
        return;
    }

    uart_printf("[DEBUG] TCP: state=%d snd_seq=%u rcv_seq=%u snd_win=%u snd_mss=%u\n",
                (int)conn->state, conn->snd_seq, conn->rcv_seq,
                (unsigned)conn->snd_win, (unsigned)conn->snd_mss);
    uart_printf("[DEBUG] rx_read=%u rx_count=%u wscale_enabled=%d snd_wscale=%u\n",
                priv->rx_read, priv->rx_count, priv->wscale_enabled,
                (unsigned)priv->snd_wscale);
    uart_printf("[DEBUG] async_count=%u async_head=%u async_cap=%u\n",
                priv->async_count, priv->async_head, priv->async_cap);
    for (unsigned i = 0; i < priv->async_count; i++) {
        tcp_async_slot_t *s = tcp_async_slot_at(priv, conn->owner_core, (priv->async_head + i) % priv->async_cap);
        uart_printf("[DEBUG] async_slots[%u]: seq=%u len=%u retries=%d\n",
                    i, s->seq, (unsigned)s->len, s->retries);
    }
    uart_printf("[DEBUG] async_short_count=%u async_short_head=%u async_short_cap=%u\n",
                priv->async_short_count, priv->async_short_head, (unsigned)TCP_ASYNC_SHORT_SLOTS);
    for (unsigned i = 0; i < priv->async_short_count; i++) {
        tcp_async_short_slot_t *s = &priv->async_short_slots[(priv->async_short_head + i) % TCP_ASYNC_SHORT_SLOTS];
        uart_printf("[DEBUG] async_short_slots[%u]: seq=%u len=%u retries=%d\n",
                    i, s->seq, (unsigned)s->len, s->retries);
    }
    uart_printf("[DEBUG] unacked_full_segments=%u\n", priv->unacked_full_segments);

    int any_ooo = 0;
    for (unsigned i = 0; i < TCP_OOO_SLOTS; i++) {
        if (priv->ooo[i].valid) {
            uart_printf("[DEBUG] ooo[%u]: seq=%u len=%u\n",
                        i, priv->ooo[i].seq, (unsigned)priv->ooo[i].len);
            any_ooo = 1;
        }
    }
    if (!any_ooo) {
        uart_printf("[DEBUG] ooo: 全スロット空き\n");
    }

    uart_printf("[DEBUG] rx_buf base=%p size=%u (mdコマンドでさらに広い範囲を確認可能)\n",
                (void *)priv->rx_buf, (unsigned)TCP_RX_BUF_SIZE);

    uint32_t dump_start = (priv->rx_read + TCP_RX_BUF_SIZE - 32u) % TCP_RX_BUF_SIZE;
    uart_printf("[DEBUG] rx_buf hexdump (rx_read-32 から192バイト、"
                "rx_read自体は+32行目の先頭):\n");
    for (uint32_t off = 0; off < 192u; off += 16u) {
        uart_printf("  +%3u:", off);
        for (uint32_t j = 0; j < 16u; j++) {
            uint32_t idx = (dump_start + off + j) % TCP_RX_BUF_SIZE;
            uart_printf(" %02x", priv->rx_buf[idx]);
        }
        uart_printf("\n");
    }
}

void tcp_accept_begin(int listener, tcp_conn_t *conn)
{
    tcp_listener_slot_t *l = tcp_listener_for(listener);
    if (!l) return;
    conn->state    = TCP_CLOSED;
    l->accept_conn  = conn;
    l->accept_ready = 0;
}

int tcp_accept_ready_poll(int listener)
{
    tcp_poll_once_ex(0);
    tcp_listener_slot_t *l = tcp_listener_for(listener);
    if (!l) return 0;
    if (tcp_abort_requested()) {
        return 0;
    }
    if (l->accept_ready) {
        l->accept_ready = 0;
        l->accept_conn  = NULL;
        return 1;
    }
    return 0;
}

void tcp_input(const uint8_t *pkt, uint16_t len, uint32_t src_ip)
{
    unsigned core = smp_core_index();

    if (len < TCP_HDR_LEN) {
        uart_printf("[TCP] ヘッダ長不足 (len=%u < %u)\n", (unsigned)len, TCP_HDR_LEN);
        return;
    }

    /* 受信バッファ由来のポインタはvolatile経由に統一する */
    const volatile uint8_t *in = pkt;

    uint16_t src_port = rd16be(in + TCP_OFF_SRC_PORT);
    uint16_t dst_port = rd16be(in + TCP_OFF_DST_PORT);

    int matched_listener = -1;
    if (in[TCP_OFF_FLAGS] & TCP_FLAG_SYN) {
        for (unsigned li = 0; li < TCP_LISTENER_TOTAL; li++) {
            tcp_listener_slot_t *l = &s_listeners[li];
            if (l->in_use &&
                l->port == dst_port &&
                (l->bound_ctx == NULL || l->bound_ctx == g_active_ctx) &&
                l->accept_conn != NULL &&
                l->accept_conn->state == TCP_CLOSED) {
                matched_listener = (int)li;
                break;
            }
        }
    }
    if (matched_listener >= 0) {
        tcp_listener_slot_t *l = &s_listeners[matched_listener];
        int slot = tcp_find_free_slot();
        if (slot < 0) {
            uart_printf("[!] TCP: 空きコネクションスロットが無く受動openのSYNを破棄 "
                        "(local_port=%u, 最大%u本)\n", dst_port, TCP_MAX_CONNS);
        }
        if (slot >= 0) {
            tcp_conn_t *aconn = l->accept_conn;
            tcp_priv_t *apriv = &s_priv[core][slot];
            tcp_priv_init(apriv, core);

            uint32_t seg_seq  = rd32be(in + TCP_OFF_SEQ);
            uint8_t  hdr_len2 = (uint8_t)(((in[TCP_OFF_DATA_OFFSET] >> 4) & 0x0Fu) * 4u);

            aconn->local_ip    = NET_SELF_IP;
            tcp_priv_try_grant_mlx5_async_overflow(apriv, core, aconn->local_ip);
            aconn->remote_ip   = src_ip;
            aconn->remote_port = src_port;
            aconn->local_port  = dst_port;
            aconn->state       = TCP_SYN_RCVD;
            aconn->snd_seq     = (uint32_t)timer_now();  /* ISN(tcp_connect()と同じ採り方) */

            aconn->owner_core = core;
            s_conns[core][slot] = aconn;

            aconn->rcv_seq = seg_seq + 1;  /* SYN消費分 */
            aconn->snd_mss = TCP_MSS_DEFAULT_RFC879;
            if (hdr_len2 > TCP_HDR_LEN && hdr_len2 <= len) {
                tcp_parse_syn_options(aconn, apriv, in + TCP_HDR_LEN, (uint8_t)(hdr_len2 - TCP_HDR_LEN));
            }
            aconn->snd_win = rd16be(in + TCP_OFF_WINDOW);

            uart_printf("[TCP] accept: SYN受信、SYN|ACK送信 (local_port=%u, slot=%d)\n",
                        dst_port, slot);

            tcp_send_segment(aconn, apriv, TCP_FLAG_SYN | TCP_FLAG_ACK, NULL, 0);

            aconn->snd_seq++;  /* SYNは1バイト分のシーケンス番号を消費する */
            apriv->expected_ack = aconn->snd_seq;
            apriv->ack_received = 0;
            return;
        }
    }

    tcp_conn_t *conn = NULL;
    tcp_priv_t *priv = NULL;
    for (unsigned i = 0; i < TCP_MAX_CONNS; i++) {
        if (s_conns[core][i] != NULL &&
            src_ip == s_conns[core][i]->remote_ip &&
            src_port == s_conns[core][i]->remote_port &&
            dst_port == s_conns[core][i]->local_port) {
            conn = s_conns[core][i];
            priv = &s_priv[core][i];
            break;
        }
    }
    if (!conn) {
        if (in[TCP_OFF_FLAGS] & TCP_FLAG_FIN) {
            tcp_timewait_t *tw = tcp_timewait_find(src_ip, src_port, dst_port);
            if (tw) {
                uint8_t fin_hdr_len = (uint8_t)(((in[TCP_OFF_DATA_OFFSET] >> 4) & 0x0Fu) * 4u);
                if (fin_hdr_len >= TCP_HDR_LEN && fin_hdr_len <= len) {
                    uint32_t fin_seq = rd32be(in + TCP_OFF_SEQ);
                    uint16_t fin_payload_len = (uint16_t)(len - fin_hdr_len);
                    tcp_send_bare_ack(tw->local_ip, tw->local_port, tw->remote_ip, tw->remote_port,
                                       tw->local_seq, fin_seq + fin_payload_len + 1u);
                }
            }
        }
        return;  /* どのアクティブコネクション宛でもない */
    }

    int hw_ok = eth_rx_hw_csum_ok();
    if(ts_log_mode()&TS_MODE_HOTPATH) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_input, 0), tcp_conn_arg(conn, len));
    if (!hw_ok) {
        uint8_t src_ip_octets[4];
        uint8_t dst_ip_octets[4];
        ip_to_octets(src_ip, src_ip_octets);
        ip_to_octets(conn->local_ip, dst_ip_octets);
        uint16_t csum_check = pseudo_header_checksum(src_ip_octets, dst_ip_octets,
                                                      IP_PROTO_TCP, pkt, len);
        if (csum_check != 0) {
            if(ts_log_mode()&TS_MODE_HOTPATH) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_input, 1), tcp_conn_arg(conn, len));
            uart_printf("[TCP] チェックサム不正 (計算結果=0x%04X、0であるべき) セグメント破棄\n",
                        csum_check);
            return;
        }
    }
    if(ts_log_mode()&TS_MODE_HOTPATH) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_input, 2), tcp_conn_arg(conn, len));

    uint32_t seq   = rd32be(in + TCP_OFF_SEQ);
    uint32_t ack   = rd32be(in + TCP_OFF_ACK);
    uint8_t  flags = in[TCP_OFF_FLAGS];
    uint8_t  hdr_len = (uint8_t)(((in[TCP_OFF_DATA_OFFSET] >> 4) & 0x0Fu) * 4u);

    if (hdr_len < TCP_HDR_LEN || hdr_len > len) {
        uart_printf("[TCP] 不正なヘッダ長 (hdr_len=%u len=%u) 無視\n",
                    hdr_len, (unsigned)len);
        return;
    }

    const volatile uint8_t *payload = in + hdr_len;
    uint16_t payload_len = (uint16_t)(len - hdr_len);

    if (flags & TCP_FLAG_RST) {
        uart_printf("[TCP] RST受信、コネクションを閉じる\n");
        conn->state = TCP_CLOSED;
        for (unsigned i = 0; i < TCP_MAX_CONNS; i++) {
            if (s_conns[core][i] == conn) {
                s_conns[core][i] = NULL;
                break;
            }
        }
        return;
    }

    if (priv->wscale_enabled) {
        conn->snd_win = (uint32_t)rd16be(in + TCP_OFF_WINDOW) << priv->snd_wscale;
    } else {
        conn->snd_win = rd16be(in + TCP_OFF_WINDOW);
    }

    switch (conn->state) {
    case TCP_SYN_RCVD:
        if ((flags & TCP_FLAG_ACK) && ack == priv->expected_ack) {
            priv->snd_una = ack;
            conn->state = TCP_ESTABLISHED;
            tcp_cwnd_init(conn, priv);
            for (unsigned li = 0; li < TCP_LISTENER_TOTAL; li++) {
                if (s_listeners[li].in_use && s_listeners[li].accept_conn == conn) {
                    s_listeners[li].accept_ready = 1;
                    break;
                }
            }
            uart_printf("[TCP] accept: ESTABLISHED (peer MSS=%u, 初期cwnd=%u)\n",
                        conn->snd_mss, priv->cwnd);
        }
        break;

    case TCP_SYN_SENT:
        if ((flags & (TCP_FLAG_SYN | TCP_FLAG_ACK)) == (TCP_FLAG_SYN | TCP_FLAG_ACK) &&
            ack == priv->expected_ack) {
            conn->rcv_seq = seq + 1;
            conn->state = TCP_ESTABLISHED;
            priv->ack_received = 1;
            tcp_parse_syn_options(conn, priv, in + TCP_HDR_LEN, (uint8_t)(hdr_len - TCP_HDR_LEN));
            conn->snd_seq = ack;
            tcp_send_segment(conn, priv, TCP_FLAG_ACK, NULL, 0);
        }
        break;

    case TCP_ESTABLISHED:
        if (flags & TCP_FLAG_ACK) {
            if (ack == priv->expected_ack) {
                priv->ack_received = 1;  /* 単発の信頼送信(tcp_send_reliable())向け */
            }
            if (tcp_seq_gt(ack, priv->snd_una)) {
                priv->snd_una = ack;     /* パイプライン送信(tcp_send())向け、累積ACKで進める */
                priv->ack_advanced = 1;
            }
            if(ts_log_mode()&TS_MODE_HOTPATH) ts_log_tcp_ack(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_input, 3), (uint8_t)tcp_conn_slot(conn),
                           seq, ack, conn->snd_win, flags);
        }
        if (flags & TCP_FLAG_FIN) {
            uint32_t free_space = TCP_RX_BUF_SIZE - priv->rx_count;
            if (payload_len > 0 && (priv->recv_upcall || payload_len <= free_space)) {
                tcp_deliver_data(priv, payload, payload_len);
            }
            conn->rcv_seq = seq + payload_len + 1;
            tcp_send_segment(conn, priv, TCP_FLAG_ACK, NULL, 0);
            conn->state = TCP_CLOSE_WAIT;
            priv->fin_received = 1;
            if(ts_log_mode()&TS_MODE_HOTPATH) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_input, 4), tcp_conn_arg(conn, payload_len));
            uart_printf("[TCP] FIN受信、ACK返送してCLOSE_WAITへ遷移\n");
        } else if (payload_len > 0) {
            uint32_t free_space = TCP_RX_BUF_SIZE - priv->rx_count;
            int accepted_inorder = 0;
            if (seq == conn->rcv_seq && (priv->recv_upcall || payload_len <= free_space)) {
                accepted_inorder = 1;
                tcp_deliver_data(priv, payload, payload_len);
                conn->rcv_seq += payload_len;
                if(ts_log_mode()&TS_MODE_HOTPATH) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_input, 5), tcp_conn_arg(conn, payload_len));

                for (;;) {
                    int spliced = 0;
                    free_space = TCP_RX_BUF_SIZE - priv->rx_count;
                    for (unsigned i = 0; i < TCP_OOO_SLOTS; i++) {
                        if (priv->ooo[i].valid && priv->ooo[i].seq == conn->rcv_seq &&
                            (priv->recv_upcall || priv->ooo[i].len <= free_space)) {
                            tcp_deliver_data(priv, priv->ooo[i].buf, priv->ooo[i].len);
                            conn->rcv_seq += priv->ooo[i].len;
                            priv->ooo[i].valid = 0;
                            spliced = 1;
                            break;
                        }
                    }
                    if (!spliced) break;
                }
            } else if (seq == conn->rcv_seq) {
                if(ts_log_mode()&TS_MODE_HOTPATH) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_input, 6), tcp_conn_arg(conn, payload_len));
            } else if (tcp_seq_gt(seq, conn->rcv_seq) && payload_len <= TCP_MSS_LOCAL) {
                int already = 0;
                for (unsigned i = 0; i < TCP_OOO_SLOTS; i++) {
                    if (priv->ooo[i].valid && priv->ooo[i].seq == seq) {
                        already = 1;
                        break;
                    }
                }
                if (!already) {
                    int stored = 0;
                    for (unsigned i = 0; i < TCP_OOO_SLOTS; i++) {
                        if (!priv->ooo[i].valid) {
                            for (uint16_t j = 0; j < payload_len; j++) {
                                priv->ooo[i].buf[j] = payload[j];
                            }
                            priv->ooo[i].seq = seq;
                            priv->ooo[i].len = payload_len;
                            priv->ooo[i].valid = 1;
                            if(ts_log_mode()&TS_MODE_HOTPATH) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_input, 7), tcp_conn_arg(conn, payload_len));
                            uart_printf("[TCP] 順序不正セグメントを先読みバッファに保持 "
                                        "(seq=%u rcv_seq=%u len=%u slot=%u)\n",
                                        seq, conn->rcv_seq, payload_len, i);
                            stored = 1;
                            break;
                        }
                    }
                    if (!stored) {
                        if(ts_log_mode()&TS_MODE_HOTPATH) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_input, 8), tcp_conn_arg(conn, payload_len));
                        uart_printf("[!] TCP: 順序不正セグメントを破棄(先読みバッファ満杯 "
                                    "TCP_OOO_SLOTS=%u) (seq=%u rcv_seq=%u len=%u)\n",
                                    TCP_OOO_SLOTS, seq, conn->rcv_seq, payload_len);
                    }
                }
            } else if (tcp_seq_gt(seq, conn->rcv_seq)) {
                if(ts_log_mode()&TS_MODE_HOTPATH) ts_log(TS_MK(TS_FILE_TCP, TS_FUNC_tcp_input, 9), tcp_conn_arg(conn, payload_len));
            }
            if (accepted_inorder && payload_len == conn->snd_mss) {
                priv->unacked_full_segments++;
                if (priv->unacked_full_segments >= g_tcp_ack_threshold) {
                    tcp_send_segment(conn, priv, TCP_FLAG_ACK, NULL, 0);
                    priv->unacked_full_segments = 0;
                }
            } else {
                tcp_send_segment(conn, priv, TCP_FLAG_ACK, NULL, 0);
                priv->unacked_full_segments = 0;
            }
        }
        break;

    case TCP_CLOSE_WAIT:
        if (flags & TCP_FLAG_ACK) {
            if (ack == priv->expected_ack) {
                priv->ack_received = 1;
            }
            if (tcp_seq_gt(ack, priv->snd_una)) {
                priv->snd_una = ack;
                priv->ack_advanced = 1;
            }
        }
        if (flags & TCP_FLAG_FIN) {
            tcp_send_segment(conn, priv, TCP_FLAG_ACK, NULL, 0);
        }
        break;

    case TCP_LAST_ACK:
        /* tcp_close()が送った自分のFINへのACKを待っている。 */
        if ((flags & TCP_FLAG_ACK) && ack == priv->expected_ack) {
            priv->ack_received = 1;
            conn->state = TCP_CLOSED;
        }
        break;

    case TCP_FIN_WAIT_1:
        if ((flags & TCP_FLAG_ACK) && ack == priv->expected_ack) {
            priv->ack_received = 1;
            conn->state = TCP_FIN_WAIT_2;
        }
        if (flags & TCP_FLAG_FIN) {
            conn->rcv_seq = seq + 1;
            tcp_send_segment(conn, priv, TCP_FLAG_ACK, NULL, 0);
            conn->state = TCP_TIME_WAIT;
        }
        break;

    case TCP_FIN_WAIT_2:
        if (flags & TCP_FLAG_FIN) {
            conn->rcv_seq = seq + 1;
            tcp_send_segment(conn, priv, TCP_FLAG_ACK, NULL, 0);
            conn->state = TCP_TIME_WAIT;
        }
        break;

    case TCP_TIME_WAIT:
    case TCP_CLOSED:
    default:
        break;
    }
}
