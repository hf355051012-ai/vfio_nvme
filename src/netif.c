// netif.c
//
// 複数ネットワークインターフェース(netif_t)の切り替え・受信ポーリング
// 巡回。設計意図はnetif.hのコメント参照。

#include "netif.h"
#include <stddef.h>
#include "timestamp.h"   /* 同上 */
#include "cache.h"
#include "uart.h"

// マルチコア化 Phase 4(~/.claude/plans/wondrous-baking-gadget.md参照):
// 「現在アクティブなコンテキスト」(g_active_ctxマクロの実体)はコアごとに
// 独立配列のまま維持する(netif.hのg_active_ctxマクロコメント参照 --
// 「今このコアが何として振る舞うか」は本質的にコア固有の実行状態)。
netif_t *g_netif_active_slots[SMP_MAX_CORES];

// 【2026-08-08変更、job stepのctx経由リソース参照化】登録簿自体は単一の
// 共有配列へ戻した(netif.hの上記コメント参照 -- job migrationで
// コネクション生成コアと異なるコアがnetif_find_by_ip()を呼んでも
// 正しく見つけられるようにするため)。総容量は従来のコアごとの容量
// (NETIF_MAX_REGISTERED)×コア数のまま維持し、実質的な登録可能数を
// 減らさない。
#define NETIF_MAX_TOTAL (NETIF_MAX_REGISTERED * SMP_MAX_CORES)

static netif_t     *s_registered[NETIF_MAX_TOTAL];
static unsigned        s_registered_count;
static smp_spinlock_t  s_registered_lock;

void netif_activate(netif_t *ctx)
{
    g_active_ctx = ctx;
}

/* ------------------------------------------------------------------ */
/* Ethernet フレーム層(旧 eth.c の共通ディスパッチ部)                  */
/* ------------------------------------------------------------------ */

#define HANDLER_MAX 8

static struct {
    uint16_t      ethertype;
    eth_handler_t handler;
    int           used;
} g_handlers[HANDLER_MAX];

void eth_register_handler(uint16_t ethertype, eth_handler_t handler)
{
    for (int i = 0; i < HANDLER_MAX; i++) {
        if (g_handlers[i].used && g_handlers[i].ethertype == ethertype) {
            g_handlers[i].handler = handler;
            if (!handler) g_handlers[i].used = 0;
            return;
        }
    }
    if (handler) {
        for (int i = 0; i < HANDLER_MAX; i++) {
            if (!g_handlers[i].used) {
                g_handlers[i].ethertype = ethertype;
                g_handlers[i].handler   = handler;
                g_handlers[i].used      = 1;
                return;
            }
        }
        uart_printf("[eth] handler table full\n");
    }
}

/* eth_dispatch() 呼び出しのネストは無い前提の per-core スカラー。 */
static int s_rx_hw_csum_ok[SMP_MAX_CORES];

int eth_rx_hw_csum_ok(void)
{
    return s_rx_hw_csum_ok[smp_core_index()];
}

void eth_dispatch(net_buf_t *nb)
{
    if (!nb || nb->len < ETH_HDR_LEN) return;
    uint16_t etype = (uint16_t)((nb->data[12] << 8) | nb->data[13]);
    const uint8_t *src_mac = &nb->data[6];
    const uint8_t *payload = &nb->data[ETH_HDR_LEN];
    size_t plen = nb->len - ETH_HDR_LEN;

    unsigned core = smp_core_index();
    s_rx_hw_csum_ok[core] = nb->hw_csum_ok;

    for (int i = 0; i < HANDLER_MAX; i++) {
        if (g_handlers[i].used && g_handlers[i].ethertype == etype) {
            g_handlers[i].handler(payload, plen, src_mac); // -> arp_handle_frame / ip_handle_frame
            break;
        }
    }
    s_rx_hw_csum_ok[core] = 0;
}

void eth_get_mac(uint8_t mac[ETH_ALEN])
{
    for (int i = 0; i < ETH_ALEN; i++) {
        mac[i] = g_active_ctx ? g_active_ctx->mac[i] : 0u;
    }
}

/* 以下は g_active_ctx->nic 経由の間接呼び出し。実体は mlx5_net.c の
 * s_mlx5_net_ops(定義は netif.h の nic_ops_t 参照)。 */
int eth_send_frags(const eth_frag_t *frags, unsigned frag_count)
{
    if (!g_active_ctx) {
        uart_printf("[eth] eth_send_frags: アクティブなインターフェースが無い\n");
        return -1;
    }
    return g_active_ctx->nic->send_frags(g_active_ctx->nic_priv, frags, frag_count); // -> mlx5_net_send_frags
}

int eth_send_frags_async(const eth_frag_t *frags, unsigned frag_count)
{
    if (!g_active_ctx) return -1;
    return g_active_ctx->nic->send_frags_async(g_active_ctx->nic_priv, frags, frag_count); // -> mlx5_net_send_frags_async
}

int eth_send_lso_async(const void *hdr, uint16_t hdr_len,
                       const void *payload, uint32_t payload_len, uint16_t mss)
{
    if (!g_active_ctx || !g_active_ctx->nic->send_lso) return -1;
    return g_active_ctx->nic->send_lso(g_active_ctx->nic_priv, hdr, hdr_len, payload, payload_len, mss); // -> mlx5_net_send_lso_async
}

unsigned eth_tx_wait_free_slot(void)
{
    if (!g_active_ctx) return 0;
    return g_active_ctx->nic->tx_wait_free_slot(g_active_ctx->nic_priv); // -> mlx5_net_tx_wait_free_slot
}

/* nb は net_buf.c の一般プール由来で Normal cacheable。そのまま NIC の
 * DMA ソースになるため、CPU の書き込みを Point of Coherency までクリーン
 * してから渡す(cache.h のコメント参照)。 */
int eth_send(net_buf_t *nb)
{
    if (!nb) return -1;
    if (nb->len < ETH_HDR_LEN || nb->len > NET_BUF_SIZE) {
        uart_printf("[eth] eth_send: 不正なフレーム長 (%u)\n", (unsigned)nb->len);
        net_buf_free(nb);
        return -1;
    }
    dcache_clean_range(nb->data, nb->len);
    eth_frag_t frag = { nb->data, nb->len };
    int ret = eth_send_frags(&frag, 1);
    net_buf_free(nb);
    return ret;
}

void netif_register(netif_t *ctx)
{
    smp_spin_lock(&s_registered_lock);
    for (unsigned i = 0; i < s_registered_count; i++) {
        if (s_registered[i] == ctx) {
            smp_spin_unlock(&s_registered_lock);
            return; // 既に登録済み
        }
    }
    if (s_registered_count < NETIF_MAX_TOTAL) {
        /* このコンテキストの実ハードウェアを実際にポーリングして良いのは
         * 登録した瞬間のコアだけに固定する(netif.hのnetif_t.owner_core
         * コメント参照)。 */
        ctx->owner_core = smp_core_index();
        ctx->is_poll_owner = 1;
        s_registered[s_registered_count++] = ctx;
    }
    smp_spin_unlock(&s_registered_lock);
}

void netif_set_owner_core(netif_t *ctx, unsigned core)
{
    ctx->owner_core = core;
}

/* 検索(netif_find()/netif_find_by_ip())・巡回(net_poll_all_and_
 * dispatch())はs_registered_lockを取らずに読む。登録(netif_register())
 * は実運用上、起動シーケンス(platform_init.c等)でジョブ/メインループが
 * 走り出す前に完了しており、以後s_registered[]/s_registered_countは
 * 実質的に不変になる -- 将来登録と検索が本当に同時に起きても、
 * s_registered_countへの書き込みは各要素書き込みの*後*に行われるため、
 * 読み手は「古いcount(新エントリがまだ見えない、無害)」か「新count+
 * 正しく書き込み済みの要素」のいずれかしか観測しない(既存のg_core1_
 * heartbeat等と同じ、このプロジェクトが単純なカウンタ/フラグ共有に
 * 対して採用している規約に倣う)。 */

netif_t *netif_find(const char *name)
{
    for (unsigned i = 0; i < s_registered_count; i++) {
        const char *a = s_registered[i]->name;
        const char *b = name;
        unsigned j = 0;
        while (a[j] != '\0' && b[j] != '\0' && a[j] == b[j]) j++;
        if (a[j] == '\0' && b[j] == '\0') {
            return s_registered[i];
        }
    }
    return NULL;
}

netif_t *netif_find_by_ip(uint32_t ip)
{
    for (unsigned i = 0; i < s_registered_count; i++) {
        if (s_registered[i]->ip == ip) {
            return s_registered[i];
        }
    }
    return NULL;
}

/* 【2026-08-08追加、telnetのコアごと分離用】受信フレームの宛先IP
 * (ARPならtpa、IPv4ならdst_ip)を読み、pollerと同じ物理NIC(nic/nic_priv
 * が一致)を共有する別名ctx(netif_register_alias()参照)の中にそのIPを
 * 名乗るものがあればそれを返す。無ければpoller自身を返す(通常の単一IP
 * 運用、または一致無し=ARP/IPハンドラ側の既存の「自機宛でなければ無視」
 * チェックへそのまま委ねる)。
 *
 * オフセットはEthernetヘッダ(14バイト)の直後からの固定値
 * (ARP tpa=RFC826のEthernet/IPv4形式で24、IPv4 dst_ip=RFC791の
 * オプション無しヘッダで16、いずれもarp.h/ip.cのオフセット定義と同じ
 * 値の再掲であり、独自に導出したものではない)。1バイトずつの読み出し
 * のみを行い、複数バイトを一度に読む多バイトアクセスは行わない(net.hの
 * 「多バイトフィールドアクセスはバイト単位で」という規約と同じ理由)。 */
static netif_t *netif_resolve_frame_owner(netif_t *poller, const net_buf_t *nb)
{
    if (nb->len < 14u + 20u) return poller;  /* ARP/IPどちらの最小長にも満たない */

    uint16_t etype = (uint16_t)(((unsigned)nb->data[12] << 8) | (unsigned)nb->data[13]);
    const uint8_t *tgt;
    if (etype == 0x0806u && nb->len >= 14u + 28u) {
        tgt = &nb->data[14u + 24u];  /* ARP: Target Protocol Address */
    } else if (etype == 0x0800u) {
        tgt = &nb->data[14u + 16u]; /* IPv4: Destination Address */
    } else {
        return poller;
    }
    uint32_t target_ip = ((uint32_t)tgt[0] << 24) | ((uint32_t)tgt[1] << 16) |
                          ((uint32_t)tgt[2] << 8) | (uint32_t)tgt[3];
    if (target_ip == poller->ip) return poller;

    for (unsigned i = 0; i < s_registered_count; i++) {
        netif_t *c = s_registered[i];
        if (c != poller && c->nic == poller->nic && c->nic_priv == poller->nic_priv &&
            c->ip == target_ip) {
            return c;
        }
    }
    return poller;
}

/* 2026-08-10、実機で発見した本物のバグの修正: 以前は1回の呼び出しで
 * ctxあたり最大1フレームしかdrainしなかった。mlx5のRQ用CQ(64エントリ
 * 固定、mlx5.cのlog_cq_size=6参照)は、LSO(1回のWQEポストでHWが複数の
 * 実セグメントを連続送出する)によって短時間に複数フレームがまとめて
 * 到着するようになったところ、1tickあたり1フレームしかdrainしない
 * このループの速度に受信が追いつかず、CQが物理的に溢れる
 * (QUERY_CQのstatus=9=MLX5_CQC_STATUS_CQ_OVERFLOW)実機バグを引き起こして
 * いた。CQが一度溢れるとHWはそれ以降の完了を一切書き込まなくなるため、
 * 実際にはMACレベルで正しく受信できているフレーム(PPCNTのrx_frames_ok
 * は増え続ける)が、ソフトウェアには二度と届いたことにならず、TCP層が
 * 永久にそのバイトのACKを送れなくなる(送信側は再送してもCQが死んでいる
 * ので同じ理由で失敗し続ける、tcp_async_poll()の「재송上限到達」の
 * 直接の原因)。診断はmlx5_monitor_dump_saved()の実機ダンプで確定
 * (CLAUDE.md参照)。
 * 修正: 1回の呼び出しでctxあたり最大MLX5_NET_POLL_BATCH_MAX(=CQ全体を
 * 1tickで確実に空にできる、CQ深さ64と同値)フレームまでdrainするよう
 * ループ化した -- 通常のRP1側(1フレーム到着ごとに1回のpoll_recv()で
 * 十分)には影響なし(2回目以降の呼び出しがNULLで即座に抜けるだけ)。 */
#define NET_POLL_BATCH_MAX 64u

int net_poll_all_and_dispatch(void)
{
    unsigned core = smp_core_index();
    netif_t *prev = g_active_ctx;
    int got_frame = 0;

    for (unsigned i = 0; i < s_registered_count; i++) {
        netif_t *ctx = s_registered[i];
        if (ctx->owner_core != core || !ctx->is_poll_owner) {
            /* このコンテキストの実ハードウェアは別コアの担当、または
             * 自分ではポーリングしない別名ctx(netif.hのnetif_t.
             * is_poll_ownerコメント参照)-- ここでは一切触らない。 */
            continue;
        }
        netif_activate(ctx);
        for (unsigned n = 0; n < NET_POLL_BATCH_MAX; n++) {
            net_buf_t *nb = ctx->nic->poll_recv(ctx->nic_priv); // -> rp1_poll_recv / mlx5_net_poll_recv
            if (!nb) {
                break;
            }
            got_frame = 1;
            netif_t *owner = netif_resolve_frame_owner(ctx, nb);
            if (owner != ctx) {
                netif_activate(owner);
            }
            eth_dispatch(nb);
            net_buf_free(nb);
            if (owner != ctx) {
                netif_activate(ctx);
            }
        }
    }

    netif_activate(prev);
    return got_frame;
}
