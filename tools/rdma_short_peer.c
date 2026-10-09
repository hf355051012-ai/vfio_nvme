/* rdma_short_peer -- `rshort`(src/rdma_short.c)の相手。Linux の librdmacm +
 * libibverbs で待ち受け、MR を 1 枚登録して、そのアドレスと rkey を
 * **CM REP の private data** で返す。データ経路は相手(自作スタック)が
 * 一方的に RDMA WRITE / READ / ATOMIC を打ち込むだけなので、こちらの CPU は
 * 何もしない(Linux の HCA が responder として処理する)。
 *
 * MR の配置(src/rdma_short.h と同じ取り決め):
 *   [0, 4096)      データ領域。接続のたびに (i*7+3) & 0xff で初期化
 *   [4096, 4608)   8 バイトの atomic 語 x 64(初期値 0)
 *   [4608, 4616)   エンディアン判定用の語(ホスト順 = LE で 0x0102030405060708)
 *
 * kill -USR1 で、データ領域 4096B + atomic 語 2 個 の FNV-1a 64 を出す
 * (`rshort verify` が最後に出す「期待 hash」と突き合わせる)。
 *
 * -c <ip> を付けると比較基準のクライアント(libibverbs)になる(「クライアント」節)。
 *
 * ビルド: gcc -O2 -Wall -Wextra -o rdma_short_peer rdma_short_peer.c -lrdmacm -libverbs
 * 実行:   ./rdma_short_peer [-a 待ち受けIP] [-p port] [-s MRバイト数]
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <endian.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <rdma/rdma_cma.h>
#include <infiniband/verbs.h>

#define DATA_BYTES   4096u
#define ATOMIC_OFF   4096u
#define ATOMIC_WORDS 64u
#define PROBE_OFF    4608u
#define PRIV_MAGIC   0x52534854u /* 'RSHT' */

static volatile sig_atomic_t g_dump;
static volatile sig_atomic_t g_quit;

static void on_usr1(int s) { (void)s; g_dump = 1; }
static void on_int(int s)  { (void)s; g_quit = 1; }

typedef struct {
    struct rdma_cm_id *id;
    struct ibv_pd *pd;
    struct ibv_cq *cq;
    struct ibv_mr *mr;
    uint8_t *buf;
} conn_t;

static size_t g_mr_bytes = 1u << 20;

static void init_region(uint8_t *b) {
    for (uint32_t i = 0; i < DATA_BYTES; i++) b[i] = (uint8_t)(i * 7u + 3u);
    memset(b + ATOMIC_OFF, 0, ATOMIC_WORDS * 8u);
    uint64_t probe = 0x0102030405060708ull; /* ホスト順(x86 = LE)*/
    memcpy(b + PROBE_OFF, &probe, 8);
}

static uint64_t fnv(uint64_t h, const uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) {
        h ^= p[i];
        h *= 0x100000001b3ull;
    }
    return h;
}

static void dump(const conn_t *c, const char *why) {
    if (!c->buf) {
        printf("[peer] %s: 接続なし\n", why);
        fflush(stdout);
        return;
    }
    /* NIC が書いた内容を確実に読む(x86 は DMA コヒーレントなので volatile で足りる)。 */
    __atomic_thread_fence(__ATOMIC_SEQ_CST);
    uint64_t h = fnv(0xcbf29ce484222325ull, c->buf, DATA_BYTES);
    h = fnv(h, c->buf + ATOMIC_OFF, 16);
    uint64_t w0, w1;
    memcpy(&w0, c->buf + ATOMIC_OFF, 8);
    memcpy(&w1, c->buf + ATOMIC_OFF + 8, 8);
    printf("[peer] %s: hash=%016llx  語0=%llu 語1=%llu  data[0..15]=",
           why, (unsigned long long)h, (unsigned long long)w0, (unsigned long long)w1);
    for (int i = 0; i < 16; i++) printf("%02x", c->buf[i]);
    printf("\n");
    fflush(stdout);
}

static void conn_free(conn_t *c) {
    if (c->id && c->id->qp) rdma_destroy_qp(c->id);
    if (c->mr) ibv_dereg_mr(c->mr);
    if (c->cq) ibv_destroy_cq(c->cq);
    if (c->pd) ibv_dealloc_pd(c->pd);
    if (c->id) rdma_destroy_id(c->id);
    free(c->buf);
    memset(c, 0, sizeof(*c));
}

static int on_connect_request(struct rdma_cm_event *ev, conn_t *c) {
    struct rdma_cm_id *id = ev->id;
    c->id = id;
    c->pd = ibv_alloc_pd(id->verbs);
    c->cq = ibv_create_cq(id->verbs, 64, NULL, NULL, 0);
    if (!c->pd || !c->cq) {
        perror("[peer] alloc_pd/create_cq");
        return -1;
    }
    if (posix_memalign((void **)&c->buf, 4096, g_mr_bytes) != 0) return -1;
    memset(c->buf, 0, g_mr_bytes);
    init_region(c->buf);
    c->mr = ibv_reg_mr(c->pd, c->buf, g_mr_bytes,
                       IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE |
                       IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_ATOMIC);
    if (!c->mr) {
        perror("[peer] ibv_reg_mr");
        return -1;
    }
    struct ibv_qp_init_attr qa;
    memset(&qa, 0, sizeof(qa));
    qa.send_cq = c->cq;
    qa.recv_cq = c->cq;
    qa.qp_type = IBV_QPT_RC;
    qa.cap.max_send_wr = 16;
    qa.cap.max_recv_wr = 16;
    qa.cap.max_send_sge = 1;
    qa.cap.max_recv_sge = 1;
    if (rdma_create_qp(id, c->pd, &qa) != 0) {
        perror("[peer] rdma_create_qp");
        return -1;
    }

    /* private data はすべて BE。相手は rdma_cm.c の rep_priv で受け取る。 */
    uint8_t priv[32];
    memset(priv, 0, sizeof(priv));
    uint32_t v32 = htobe32(PRIV_MAGIC);
    memcpy(&priv[0], &v32, 4);
    v32 = htobe32(1);
    memcpy(&priv[4], &v32, 4);
    uint64_t v64 = htobe64((uint64_t)(uintptr_t)c->buf);
    memcpy(&priv[8], &v64, 8);
    v32 = htobe32(c->mr->rkey);
    memcpy(&priv[16], &v32, 4);
    v32 = htobe32((uint32_t)g_mr_bytes);
    memcpy(&priv[20], &v32, 4);

    struct ibv_device_attr da;
    ibv_query_device(id->verbs, &da);
    struct rdma_conn_param cp;
    memset(&cp, 0, sizeof(cp));
    cp.private_data = priv;
    cp.private_data_len = sizeof(priv);
    /* 相手が同時に投げてくる read / atomic の数 = こちらの max_dest_rd_atomic。 */
    cp.responder_resources = (uint8_t)da.max_qp_rd_atom;
    cp.initiator_depth = (uint8_t)da.max_qp_init_rd_atom;
    cp.rnr_retry_count = 7;
    if (ev->param.conn.initiator_depth < cp.responder_resources) {
        cp.responder_resources = ev->param.conn.initiator_depth;
    }
    if (rdma_accept(id, &cp) != 0) {
        perror("[peer] rdma_accept");
        return -1;
    }
    char ip[64] = "?";
    struct sockaddr_in *sa = (struct sockaddr_in *)rdma_get_peer_addr(id);
    inet_ntop(AF_INET, &sa->sin_addr, ip, sizeof(ip));
    printf("[peer] 接続要求 from %s: qpn=%u MR addr=%p rkey=0x%08x len=%zu responder_resources=%u "
           "(相手の initiator_depth=%u)\n",
           ip, id->qp->qp_num, (void *)c->buf, c->mr->rkey, g_mr_bytes,
           cp.responder_resources, ev->param.conn.initiator_depth);
    fflush(stdout);
    return 0;
}


/* ================================================================
 * クライアント(比較基準): libibverbs で `rshort` と同じ測り方をする。
 *   ./rdma_short_peer -c <server_ip> [-p port] sweep [回数]
 *   ./rdma_short_peer -c <server_ip> lat <w|r|cas|faa> <len> [回数]
 *   ./rdma_short_peer -c <server_ip> bw  <w|r|cas|faa> <len> <qd> [ms]
 * 測る区間・signal の間隔・宛先の散らし方・ドアベルのまとめ方は
 * src/rdma_short.c と揃えてある(違うのはドライバが mlx5_core + libmlx5 なことだけ)。
 * ================================================================ */
#include <x86intrin.h>
#include <time.h>

enum { OP_W = 0, OP_R, OP_CAS, OP_FAA };
static const char *const op_name[] = { "write", "read", "cas", "faa" };

typedef struct {
    struct rdma_event_channel *ch;
    struct rdma_cm_id *id;
    struct ibv_pd *pd;
    struct ibv_cq *cq;
    struct ibv_mr *mr;
    uint8_t *lbuf;
    uint64_t raddr;
    uint32_t rkey;
    int res_be;
    uint32_t inline_max;   /* write をこの長さまで inline で出す */
} cli_t;

static uint64_t g_khz;
static uint32_t g_lat[200000];

static uint64_t mono_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static void calib(void) {
    uint64_t t0 = mono_ns(), c0 = __rdtsc();
    while (mono_ns() - t0 < 50000000ull) {
    }
    uint64_t t1 = mono_ns(), c1 = __rdtsc();
    g_khz = (c1 - c0) * 1000000ull / (t1 - t0);
}

static int wait_ev(cli_t *c, enum rdma_cm_event_type want, struct rdma_cm_event **out) {
    struct rdma_cm_event *ev;
    if (rdma_get_cm_event(c->ch, &ev) != 0) return -1;
    if (ev->event != want) {
        fprintf(stderr, "[cli] 期待 %s / 実際 %s (status=%d)\n", rdma_event_str(want),
                rdma_event_str(ev->event), ev->status);
        rdma_ack_cm_event(ev);
        return -1;
    }
    if (out) *out = ev; else rdma_ack_cm_event(ev);
    return 0;
}

/* sig_all=1 で QP を sq_sig_all にする。**Linux の mlx5_ib はそのとき requester の
 * scatter to CQE(cs_req)を自動で有効にする**(configure_requester_scat_cqe())ので、
 * qd=1 と read / atomic はこちらで測る(rshort も同じ機能を使っている)。 */
static int cli_connect(cli_t *c, const char *ip, int port, int sig_all) {
    memset(c, 0, sizeof(*c));
    c->inline_max = 32;
    c->ch = rdma_create_event_channel();
    if (!c->ch || rdma_create_id(c->ch, &c->id, NULL, RDMA_PS_TCP) != 0) return -1;
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    inet_pton(AF_INET, ip, &sa.sin_addr);
    if (rdma_resolve_addr(c->id, NULL, (struct sockaddr *)&sa, 2000) != 0 ||
        wait_ev(c, RDMA_CM_EVENT_ADDR_RESOLVED, NULL) != 0 ||
        rdma_resolve_route(c->id, 2000) != 0 ||
        wait_ev(c, RDMA_CM_EVENT_ROUTE_RESOLVED, NULL) != 0) {
        fprintf(stderr, "[cli] アドレス/経路の解決に失敗\n");
        return -1;
    }
    c->pd = ibv_alloc_pd(c->id->verbs);
    c->cq = ibv_create_cq(c->id->verbs, 1024, NULL, NULL, 0);
    if (posix_memalign((void **)&c->lbuf, 4096, 65536) != 0) return -1;
    memset(c->lbuf, 0, 65536);
    c->mr = ibv_reg_mr(c->pd, c->lbuf, 65536, IBV_ACCESS_LOCAL_WRITE);
    struct ibv_qp_init_attr qa;
    memset(&qa, 0, sizeof(qa));
    qa.send_cq = c->cq;
    qa.recv_cq = c->cq;
    qa.qp_type = IBV_QPT_RC;
    qa.cap.max_send_wr = 256;
    qa.cap.max_recv_wr = 1;
    qa.cap.max_send_sge = 1;
    qa.cap.max_recv_sge = 1;
    qa.cap.max_inline_data = 64;
    qa.sq_sig_all = sig_all;
    if (!c->pd || !c->cq || !c->mr || rdma_create_qp(c->id, c->pd, &qa) != 0) {
        perror("[cli] 資源の確保");
        return -1;
    }
    struct rdma_conn_param cp;
    memset(&cp, 0, sizeof(cp));
    cp.initiator_depth = 16;
    cp.responder_resources = 16;
    cp.retry_count = 7;
    cp.rnr_retry_count = 7;
    struct rdma_cm_event *ev;
    if (rdma_connect(c->id, &cp) != 0 || wait_ev(c, RDMA_CM_EVENT_ESTABLISHED, &ev) != 0) {
        fprintf(stderr, "[cli] 接続失敗\n");
        return -1;
    }
    const uint8_t *pd = ev->param.conn.private_data;
    uint32_t magic, rkey;
    uint64_t addr;
    memcpy(&magic, pd, 4);
    memcpy(&addr, pd + 8, 8);
    memcpy(&rkey, pd + 16, 4);
    c->raddr = be64toh(addr);
    c->rkey = be32toh(rkey);
    rdma_ack_cm_event(ev);
    if (be32toh(magic) != PRIV_MAGIC) {
        fprintf(stderr, "[cli] private data が rdma_short_peer のものではない\n");
        return -1;
    }
    printf("[cli] 接続 qpn=%u MR addr=0x%llx rkey=0x%08x max_inline=%u\n", c->id->qp->qp_num,
           (unsigned long long)c->raddr, c->rkey, qa.cap.max_inline_data);
    return 0;
}

static void cli_fill_wr(cli_t *c, struct ibv_send_wr *wr, struct ibv_sge *sge, int op, uint32_t len,
                        uint64_t roff, unsigned slot, const uint8_t *src, uint64_t swap_add,
                        uint64_t cmp, int signaled, uint64_t wr_id) {
    memset(wr, 0, sizeof(*wr));
    sge->lkey = c->mr->lkey;
    sge->addr = (uintptr_t)(c->lbuf + slot * 64u);
    sge->length = (op == OP_CAS || op == OP_FAA) ? 8u : len;
    wr->wr_id = wr_id;
    wr->sg_list = sge;
    wr->num_sge = 1;
    wr->send_flags = signaled ? IBV_SEND_SIGNALED : 0;
    switch (op) {
    case OP_W:
        wr->opcode = IBV_WR_RDMA_WRITE;
        if (len <= c->inline_max) {
            wr->send_flags |= IBV_SEND_INLINE;
            sge->addr = (uintptr_t)src;
        } /* それ以外は lbuf の slot(呼び出し側が src を写しておく)*/
        wr->wr.rdma.remote_addr = c->raddr + roff;
        wr->wr.rdma.rkey = c->rkey;
        break;
    case OP_R:
        wr->opcode = IBV_WR_RDMA_READ;
        wr->wr.rdma.remote_addr = c->raddr + roff;
        wr->wr.rdma.rkey = c->rkey;
        break;
    case OP_CAS:
        wr->opcode = IBV_WR_ATOMIC_CMP_AND_SWP;
        wr->wr.atomic.remote_addr = c->raddr + roff;
        wr->wr.atomic.rkey = c->rkey;
        wr->wr.atomic.compare_add = cmp;
        wr->wr.atomic.swap = swap_add;
        break;
    default:
        wr->opcode = IBV_WR_ATOMIC_FETCH_AND_ADD;
        wr->wr.atomic.remote_addr = c->raddr + roff;
        wr->wr.atomic.rkey = c->rkey;
        wr->wr.atomic.compare_add = swap_add;
        break;
    }
}

static uint64_t cli_one(cli_t *c, int op, uint32_t len, uint64_t roff, const uint8_t *src,
                        uint64_t swap_add, uint64_t cmp) {
    struct ibv_send_wr wr, *bad;
    struct ibv_sge sge;
    struct ibv_wc wc;
    uint64_t t0 = __rdtsc();
    cli_fill_wr(c, &wr, &sge, op, len, roff, 0, src, swap_add, cmp, 1, 0);
    if (ibv_post_send(c->id->qp, &wr, &bad) != 0) {
        perror("[cli] ibv_post_send");
        return 0;
    }
    int n;
    while ((n = ibv_poll_cq(c->cq, 1, &wc)) == 0) {
    }
    uint64_t t1 = __rdtsc();
    if (n < 0 || wc.status != IBV_WC_SUCCESS) {
        fprintf(stderr, "[cli] %s: 完了エラー %s\n", op_name[op], ibv_wc_status_str(wc.status));
        return 0;
    }
    return t1 - t0 ? t1 - t0 : 1;
}

static uint64_t cli_res(cli_t *c) {
    uint64_t v;
    memcpy(&v, c->lbuf, 8);
    return c->res_be ? be64toh(v) : v;
}

static int cmp_u32(const void *a, const void *b) {
    uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b;
    return (x > y) - (x < y);
}

static int cli_lat(cli_t *c, int op, uint32_t len, uint32_t iters, int quiet, uint32_t *p50o,
                   uint32_t *avgo) {
    if (iters > 200000u) iters = 200000u;
    if (iters == 0) iters = 1;
    uint8_t src[32];
    for (unsigned j = 0; j < len; j++) src[j] = (uint8_t)(0x5Au ^ j);
    uint32_t warm = iters / 10u + 100u;
    uint64_t cur = 0, sum = 0;
    if (op == OP_CAS) {
        if (!cli_one(c, OP_FAA, 8, ATOMIC_OFF, NULL, 0, 0)) return -1;
        cur = cli_res(c);
    }
    for (uint32_t i = 0; i < warm + iters; i++) {
        uint64_t cyc;
        if (op == OP_CAS) {
            cyc = cli_one(c, op, 8, ATOMIC_OFF, NULL, cur + 1, cur);
            if (cyc && cli_res(c) != cur) {
                fprintf(stderr, "[cli] cas 失敗(期待 %llu 実際 %llu)\n", (unsigned long long)cur,
                        (unsigned long long)cli_res(c));
                return -1;
            }
            cur++;
        } else {
            cyc = cli_one(c, op, len, (op == OP_FAA) ? ATOMIC_OFF : 0, src, 1, 0);
        }
        if (!cyc) return -1;
        if (i >= warm) {
            uint32_t ns = (uint32_t)(cyc * 1000000ull / g_khz);
            g_lat[i - warm] = ns;
            sum += ns;
        }
    }
    qsort(g_lat, iters, sizeof(g_lat[0]), cmp_u32);
    uint32_t avg = (uint32_t)(sum / iters), p50 = g_lat[iters / 2];
    if (!quiet) {
        printf("[cli] lat %s %uB x%u: avg %u ns / min %u / p50 %u / p99 %u / p99.9 %u / max %u\n",
               op_name[op], len, iters, avg, g_lat[0], p50, g_lat[(uint64_t)iters * 99 / 100],
               g_lat[(uint64_t)iters * 999 / 1000], g_lat[iters - 1]);
    }
    if (p50o) *p50o = p50;
    if (avgo) *avgo = avg;
    return 0;
}

static int cli_bw(cli_t *c, int op, uint32_t len, uint32_t qd, uint32_t ms) {
    if (qd < 1) qd = 1;
    if (qd > 128) qd = 128;
    uint32_t sig = (qd / 2) ? ((qd / 2 > 32) ? 32 : qd / 2) : 1;
    if (op != OP_W) sig = 1; /* rshort と同じ: read / atomic は全部 signaled */
    uint8_t src[32];
    for (unsigned j = 0; j < len; j++) src[j] = (uint8_t)(0xC3u ^ j);
    /* rshort と同じ: 積み上げるときの inline は 1 WQEBB に収まる 28B まで */
    c->inline_max = 28;
    for (unsigned s = 0; s < 128; s++) memcpy(c->lbuf + s * 64u, src, len);
    struct ibv_send_wr wrs[128], *bad;
    struct ibv_sge sges[128];
    struct ibv_wc wc[32];
    uint64_t posted = 0, done = 0, since = 0;
    uint64_t t0 = __rdtsc(), tend = t0 + (uint64_t)ms * g_khz, tlast = t0;
    int stopping = 0;
    for (;;) {
        if (!stopping && __rdtsc() >= tend) stopping = 1;
        unsigned n = 0;
        if (!stopping) {
            while (posted - done < qd) {
                int sgn = (++since >= sig) || (posted + 1 - done >= qd);
                uint32_t i = (uint32_t)posted;
                uint64_t roff = (op == OP_CAS || op == OP_FAA) ? ATOMIC_OFF + (i & 63u) * 8u
                                                               : (uint64_t)(i & 63u) * 64u;
                posted++;
                cli_fill_wr(c, &wrs[n], &sges[n], op, len, roff, i & 127u, src, 1, 0, sgn, posted);
                if (n) wrs[n - 1].next = &wrs[n];
                n++;
                if (sgn) since = 0;
            }
        } else if (posted != done && since != 0) {
            /* 最後が unsignaled のまま止めた。0 バイトの signaled write で締める。 */
            cli_fill_wr(c, &wrs[0], &sges[0], OP_W, 0, 0, 0, src, 0, 0, 1, posted);
            wrs[0].num_sge = 0;
            n = 1;
            since = 0;
        }
        if (n && ibv_post_send(c->id->qp, &wrs[0], &bad) != 0) {
            perror("[cli] ibv_post_send");
            return -1;
        }
        int k = ibv_poll_cq(c->cq, 32, wc);
        for (int j = 0; j < k; j++) {
            if (wc[j].status != IBV_WC_SUCCESS) {
                fprintf(stderr, "[cli] 完了エラー %s\n", ibv_wc_status_str(wc[j].status));
                return -1;
            }
            done = wc[j].wr_id;
            tlast = __rdtsc();
        }
        if (stopping && posted == done) break;
    }
    uint64_t ns = (tlast - t0) * 1000000ull / g_khz;
    uint64_t kops = ns ? posted * 1000000ull / ns : 0;
    uint64_t mb10 = ns ? posted * len * 10000ull / ns : 0;
    printf("[cli] bw %s %uB qd=%u sig=%u: %llu ops / %llu us -> %llu.%03llu Mops/s  %llu.%llu MB/s\n",
           op_name[op], len, qd, sig, (unsigned long long)posted, (unsigned long long)(ns / 1000),
           (unsigned long long)(kops / 1000), (unsigned long long)(kops % 1000),
           (unsigned long long)(mb10 / 10), (unsigned long long)(mb10 % 10));
    return 0;
}

static int parse_op(const char *s) {
    if (!strcmp(s, "w") || !strcmp(s, "write")) return OP_W;
    if (!strcmp(s, "r") || !strcmp(s, "read")) return OP_R;
    if (!strcmp(s, "cas")) return OP_CAS;
    if (!strcmp(s, "faa")) return OP_FAA;
    return -1;
}

static int client_main(const char *ip, int port, int argc, char **argv) {
    calib();
    cli_t c;
    /* 積み上げる write だけ selective signaling(sq_sig_all=0)で、それ以外は全部 signaled */
    const int bw_write = (argc >= 2 && !strcmp(argv[0], "bw") && parse_op(argv[1]) == OP_W);
    if (cli_connect(&c, ip, port, !bw_write) != 0) return 1;
    /* 元値のバイト順(rshort verify の [3] と同じ判定) */
    if (!cli_one(&c, OP_FAA, 8, PROBE_OFF, NULL, 0, 0)) return 1;
    c.res_be = (c.lbuf[0] == 0x01);
    printf("[cli] atomic の元値は %s で返る(%02x..%02x)\n", c.res_be ? "BE" : "LE", c.lbuf[0], c.lbuf[7]);
    int rc = 0;
    if (argc >= 1 && !strcmp(argv[0], "sweep")) {
        uint32_t iters = (argc >= 2) ? (uint32_t)atoi(argv[1]) : 50000u;
        static const uint32_t lens[] = { 1, 2, 4, 8, 16, 24, 28, 29, 32 };
        printf("[cli] sweep(qd=1、%u 回、単位 ns、p50 / avg)\n  len    write          read\n", iters);
        for (unsigned i = 0; i < sizeof(lens) / sizeof(lens[0]) && rc == 0; i++) {
            uint32_t wp = 0, wa = 0, rp = 0, ra = 0;
            rc |= cli_lat(&c, OP_W, lens[i], iters, 1, &wp, &wa);
            rc |= cli_lat(&c, OP_R, lens[i], iters, 1, &rp, &ra);
            printf("  %2u   %5u / %5u   %5u / %5u\n", lens[i], wp, wa, rp, ra);
        }
        uint32_t cp = 0, ca = 0, fp = 0, fa = 0;
        rc |= cli_lat(&c, OP_CAS, 8, iters, 1, &cp, &ca);
        rc |= cli_lat(&c, OP_FAA, 8, iters, 1, &fp, &fa);
        printf("  cas 8B %5u / %5u   faa 8B %5u / %5u\n", cp, ca, fp, fa);
    } else if (argc >= 3 && !strcmp(argv[0], "lat")) {
        int op = parse_op(argv[1]);
        uint32_t len = (op == OP_CAS || op == OP_FAA) ? 8u : (uint32_t)atoi(argv[2]);
        rc = (op < 0) ? -1 : cli_lat(&c, op, len, (argc >= 4) ? (uint32_t)atoi(argv[3]) : 100000u, 0, 0, 0);
    } else if (argc >= 4 && !strcmp(argv[0], "bw")) {
        int op = parse_op(argv[1]);
        uint32_t len = (op == OP_CAS || op == OP_FAA) ? 8u : (uint32_t)atoi(argv[2]);
        rc = (op < 0) ? -1 : cli_bw(&c, op, len, (uint32_t)atoi(argv[3]),
                                    (argc >= 5) ? (uint32_t)atoi(argv[4]) : 3000u);
    } else {
        fprintf(stderr, "client: sweep [n] | lat <op> <len> [n] | bw <op> <len> <qd> [ms]\n");
        rc = -1;
    }
    rdma_disconnect(c.id);
    return rc ? 1 : 0;
}

int main(int argc, char **argv) {
    const char *addr = "0.0.0.0";
    int port = 18515;
    int opt;
    const char *client_ip = NULL;
    while ((opt = getopt(argc, argv, "+a:p:s:c:")) != -1) {
        switch (opt) {
        case 'c': client_ip = optarg; break;
        case 'a': addr = optarg; break;
        case 'p': port = atoi(optarg); break;
        case 's': g_mr_bytes = (size_t)strtoull(optarg, NULL, 0); break;
        default:
            fprintf(stderr, "usage: %s [-a ip] [-p port] [-s mr_bytes]\n", argv[0]);
            return 2;
        }
    }
    if (g_mr_bytes < 8192) g_mr_bytes = 8192;
    if (client_ip) return client_main(client_ip, port, argc - optind, argv + optind);
    signal(SIGUSR1, on_usr1);
    signal(SIGINT, on_int);
    signal(SIGTERM, on_int);

    struct rdma_event_channel *ch = rdma_create_event_channel();
    struct rdma_cm_id *listen_id = NULL;
    if (!ch || rdma_create_id(ch, &listen_id, NULL, RDMA_PS_TCP) != 0) {
        perror("[peer] rdma_create_id");
        return 1;
    }
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons((uint16_t)port);
    inet_pton(AF_INET, addr, &sa.sin_addr);
    if (rdma_bind_addr(listen_id, (struct sockaddr *)&sa) != 0 || rdma_listen(listen_id, 4) != 0) {
        perror("[peer] bind/listen");
        return 1;
    }
    printf("[peer] %s:%d で待ち受け中(MR %zu バイト)。kill -USR1 %d で hash を出す\n",
           addr, port, g_mr_bytes, getpid());
    fflush(stdout);

    conn_t cur;
    memset(&cur, 0, sizeof(cur));
    while (!g_quit) {
        if (g_dump) {
            g_dump = 0;
            dump(&cur, "USR1");
        }
        struct pollfd pfd = { .fd = ch->fd, .events = POLLIN };
        int pr = poll(&pfd, 1, 100);
        if (pr <= 0) continue;
        struct rdma_cm_event *ev = NULL;
        if (rdma_get_cm_event(ch, &ev) != 0) break;
        switch (ev->event) {
        case RDMA_CM_EVENT_CONNECT_REQUEST:
            if (cur.id) { /* 1 本しか持たない。前の接続は捨てる */
                dump(&cur, "前の接続を破棄");
                rdma_disconnect(cur.id);
                conn_free(&cur);
            }
            if (on_connect_request(ev, &cur) != 0) {
                rdma_reject(ev->id, NULL, 0);
                rdma_ack_cm_event(ev); /* ack する前に id を壊すと rdma_destroy_id が待ち続ける */
                ev = NULL;
                conn_free(&cur);
            }
            break;
        case RDMA_CM_EVENT_ESTABLISHED:
            printf("[peer] 確立\n");
            fflush(stdout);
            break;
        case RDMA_CM_EVENT_DISCONNECTED:
            dump(&cur, "切断");
            rdma_ack_cm_event(ev);
            ev = NULL;
            conn_free(&cur);
            break;
        default:
            printf("[peer] CM イベント %s (status=%d)\n", rdma_event_str(ev->event), ev->status);
            fflush(stdout);
            break;
        }
        if (ev) rdma_ack_cm_event(ev);
    }
    if (cur.id) conn_free(&cur);
    rdma_destroy_id(listen_id);
    rdma_destroy_event_channel(ch);
    return 0;
}
