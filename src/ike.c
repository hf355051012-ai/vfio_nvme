/* IKEv2(RFC 7296)と、IKE の AES-GCM(RFC 5282)。説明は ike.h。
 * 形式と計算の順番は RFC 7296 の 2.13〜2.17・3 章と、strongSwan(libcharon)が実際に
 * 送るものに合わせた。 */
#include "ike.h"
#include "ipsec.h"
#include "udp.h"
#include "net.h"
#include "netif.h"
#include "crypto.h"
#include "job.h"
#include "timer.h"
#include "uart.h"
#include <string.h>

/* 交換の種類 */
#define EX_IKE_SA_INIT   34u
#define EX_IKE_AUTH      35u
#define EX_CREATE_CHILD  36u
#define EX_INFORMATIONAL 37u
/* フラグ */
#define F_INITIATOR 0x08u
#define F_RESPONSE  0x20u
/* ペイロードの種類 */
#define PL_NONE   0u
#define PL_SA     33u
#define PL_KE     34u
#define PL_IDI    35u
#define PL_IDR    36u
#define PL_AUTH   39u
#define PL_NONCE  40u
#define PL_NOTIFY 41u
#define PL_DELETE 42u
#define PL_TSI    44u
#define PL_TSR    45u
#define PL_SK     46u
/* 変換 */
#define TR_ENCR 1u
#define TR_PRF  2u
#define TR_INTEG 3u
#define TR_DH   4u
#define TR_ESN  5u
#define ENCR_AES_GCM_16   20u
#define PRF_HMAC_SHA2_256 5u
#define DH_CURVE25519     31u
#define PROTO_IKE 1u
#define PROTO_ESP 3u
/* 通知 */
#define N_NO_PROPOSAL_CHOSEN   14u
#define N_INVALID_KE_PAYLOAD   17u
#define N_AUTH_FAILED          24u
#define N_TS_UNACCEPTABLE      38u
#define N_NO_ADDITIONAL_SAS    35u
#define N_USE_TRANSPORT_MODE   16391u

#define HDR_LEN   28u
#define NONCE_LEN 32u
#define PRF_LEN   32u
#define KEY_LEN   20u      /* AES-128 の鍵 16 + salt 4 */
#define MSG_MAX   2048u
#define IKE_PEERS 4u

enum { ST_NONE = 0, ST_I_INIT, ST_I_AUTH, ST_ESTABLISHED, ST_R_INIT, ST_DELETING };

typedef struct {
    uint8_t  used;
    uint32_t peer;
    netif_t *nif;
    uint8_t  peer_mac[6];
    uint8_t  mac_known;
    char     psk[128];
    uint32_t psklen;
    /* IKE SA */
    uint8_t  state, initiator;
    uint8_t  spi_i[8], spi_r[8];
    uint8_t  ni[256], nr[256];
    uint32_t ni_len, nr_len;
    uint8_t  x_priv[32], x_pub[32];
    uint8_t  sk_d[PRF_LEN], sk_pi[PRF_LEN], sk_pr[PRF_LEN];
    uint8_t  salt_i[4], salt_r[4];
    crypto_aes128gcm_t k_i, k_r;      /* SK_ei / SK_er */
    uint8_t  msg1[MSG_MAX], msg2[MSG_MAX];   /* IKE_SA_INIT の要求と応答(AUTH の計算に使う)*/
    uint32_t msg1_len, msg2_len;
    uint32_t my_msgid;                /* こちらの次の要求の Message ID */
    uint32_t peer_msgid;              /* 相手の次の要求の Message ID */
    uint8_t  last_resp[MSG_MAX];      /* 相手の要求の再送に答え直すため */
    uint32_t last_resp_len, last_resp_msgid;
    uint8_t  last_req[MSG_MAX];       /* こちらの要求の再送 */
    uint32_t last_req_len;
    uint8_t  got_resp;                /* こちらの要求への応答が来た */
    uint32_t esp_spi_in, esp_spi_out;
    uint8_t  fail;
    /* 統計 */
    uint32_t n_up, n_rx, n_tx, n_bad;
} ike_peer_t;

static ike_peer_t s_ike[IKE_PEERS];
static int s_bound;

static ike_peer_t *find_peer(uint32_t ip)
{
    for (unsigned i = 0; i < IKE_PEERS; i++)
        if (s_ike[i].used && s_ike[i].peer == ip) return &s_ike[i];
    return NULL;
}

/* ---------------------------------------------------------------- 鍵 */

static void prf(const void *k, size_t kl, const void *m, size_t ml, uint8_t out[PRF_LEN])
{
    crypto_hmac(CRYPTO_SHA256, k, kl, m, ml, out);
}

/* prf+(RFC 7296 2.13)。T1 = prf(K, S | 0x01)、Tn = prf(K, Tn-1 | S | n)。 */
static void prf_plus(const void *k, size_t kl, const uint8_t *s, size_t sl, uint8_t *out, size_t olen)
{
    uint8_t t[PRF_LEN];
    size_t tl = 0, done = 0;
    for (uint8_t n = 1; done < olen; n++) {
        crypto_hmac_ctx_t c;
        crypto_hmac_init(&c, CRYPTO_SHA256, k, kl);
        crypto_hmac_update(&c, t, tl);
        crypto_hmac_update(&c, s, sl);
        crypto_hmac_update(&c, &n, 1);
        crypto_hmac_final(&c, t);
        tl = PRF_LEN;
        const size_t take = (olen - done < PRF_LEN) ? olen - done : PRF_LEN;
        memcpy(out + done, t, take);
        done += take;
    }
    crypto_wipe(t, sizeof(t));
}

/* IKE SA の鍵(2.14): SKEYSEED = prf(Ni | Nr, g^ir)、
 * SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr = prf+(SKEYSEED, Ni | Nr | SPIi | SPIr)。
 * AEAD なので SK_ai / SK_ar は 0 バイト。 */
static int derive_ike_keys(ike_peer_t *p, const uint8_t peer_pub[32])
{
    uint8_t shared[32], seed[PRF_LEN];
    if (crypto_x25519(shared, p->x_priv, peer_pub) != 0) return -1;
    uint8_t nn[512];
    memcpy(nn, p->ni, p->ni_len);
    memcpy(nn + p->ni_len, p->nr, p->nr_len);
    prf(nn, p->ni_len + p->nr_len, shared, 32, seed);
    uint8_t s[512 + 16];
    memcpy(s, nn, p->ni_len + p->nr_len);
    memcpy(s + p->ni_len + p->nr_len, p->spi_i, 8);
    memcpy(s + p->ni_len + p->nr_len + 8, p->spi_r, 8);
    uint8_t km[PRF_LEN + 2 * KEY_LEN + 2 * PRF_LEN];
    prf_plus(seed, PRF_LEN, s, p->ni_len + p->nr_len + 16, km, sizeof(km));
    memcpy(p->sk_d, km, PRF_LEN);
    crypto_aes128gcm_init(&p->k_i, km + PRF_LEN);
    memcpy(p->salt_i, km + PRF_LEN + 16, 4);
    crypto_aes128gcm_init(&p->k_r, km + PRF_LEN + KEY_LEN);
    memcpy(p->salt_r, km + PRF_LEN + KEY_LEN + 16, 4);
    memcpy(p->sk_pi, km + PRF_LEN + 2 * KEY_LEN, PRF_LEN);
    memcpy(p->sk_pr, km + PRF_LEN + 2 * KEY_LEN + PRF_LEN, PRF_LEN);
    crypto_wipe(shared, sizeof(shared));
    crypto_wipe(seed, sizeof(seed));
    crypto_wipe(km, sizeof(km));
    crypto_wipe(p->x_priv, sizeof(p->x_priv));
    return 0;
}

/* 子 SA の鍵(2.17): KEYMAT = prf+(SK_d, Ni | Nr)。始めた側から受けた側への向きの鍵が先。 */
static void derive_child_keys(ike_peer_t *p, uint8_t k_i2r[KEY_LEN], uint8_t k_r2i[KEY_LEN])
{
    uint8_t nn[512], km[2 * KEY_LEN];
    memcpy(nn, p->ni, p->ni_len);
    memcpy(nn + p->ni_len, p->nr, p->nr_len);
    prf_plus(p->sk_d, PRF_LEN, nn, p->ni_len + p->nr_len, km, sizeof(km));
    memcpy(k_i2r, km, KEY_LEN);
    memcpy(k_r2i, km + KEY_LEN, KEY_LEN);
    crypto_wipe(km, sizeof(km));
}

/* AUTH(2.15、事前共有鍵): prf(prf(鍵, "Key Pad for IKEv2"), 署名する並び)。
 * 署名する並び = 自分の IKE_SA_INIT のメッセージ | 相手の Nonce | prf(SK_p, ID の本体)。 */
static void compute_auth(const ike_peer_t *p, int of_initiator, const uint8_t *id_body, uint32_t id_len,
                         uint8_t out[PRF_LEN])
{
    uint8_t kpad[PRF_LEN], mid[PRF_LEN];
    prf(p->psk, p->psklen, "Key Pad for IKEv2", 17, kpad);
    prf(of_initiator ? p->sk_pi : p->sk_pr, PRF_LEN, id_body, id_len, mid);
    crypto_hmac_ctx_t c;
    crypto_hmac_init(&c, CRYPTO_SHA256, kpad, PRF_LEN);
    if (of_initiator) {
        crypto_hmac_update(&c, p->msg1, p->msg1_len);
        crypto_hmac_update(&c, p->nr, p->nr_len);
    } else {
        crypto_hmac_update(&c, p->msg2, p->msg2_len);
        crypto_hmac_update(&c, p->ni, p->ni_len);
    }
    crypto_hmac_update(&c, mid, PRF_LEN);
    crypto_hmac_final(&c, out);
    crypto_wipe(kpad, sizeof(kpad));
}

/* ---------------------------------------------------------------- メッセージの組み立て */

typedef struct {
    uint8_t *b;
    uint32_t len, cap;
    uint8_t *np;      /* 直前のペイロードの「次のペイロード」欄 */
} wbuf_t;

static uint8_t *pl_begin(wbuf_t *w, uint8_t type)
{
    if (w->len + 4u > w->cap) return NULL;
    *w->np = type;
    uint8_t *h = w->b + w->len;
    h[0] = PL_NONE;
    h[1] = 0;
    w->np = h;
    w->len += 4u;
    return h;
}

static void pl_end(wbuf_t *w, uint8_t *h)
{
    wr16be(h + 2, (uint16_t)(w->b + w->len - h));
}

static int put(wbuf_t *w, const void *d, uint32_t n)
{
    if (w->len + n > w->cap) return -1;
    memcpy(w->b + w->len, d, n);
    w->len += n;
    return 0;
}

static void put8(wbuf_t *w, uint8_t v) { put(w, &v, 1); }
static void put16(wbuf_t *w, uint16_t v) { uint8_t x[2]; wr16be(x, v); put(w, x, 2); }
static void put32(wbuf_t *w, uint32_t v) { uint8_t x[4]; wr32be(x, v); put(w, x, 4); }

static void hdr_init(wbuf_t *w, uint8_t *buf, uint32_t cap, const ike_peer_t *p, uint8_t ex,
                     uint8_t flags, uint32_t msgid)
{
    w->b = buf;
    w->cap = cap;
    memcpy(buf, p->spi_i, 8);
    memcpy(buf + 8, p->spi_r, 8);
    buf[16] = PL_NONE;
    buf[17] = 0x20;   /* 版 2.0 */
    buf[18] = ex;
    buf[19] = flags;
    wr32be(buf + 20, msgid);
    w->len = HDR_LEN;
    w->np = buf + 16;
}

static void hdr_finish(wbuf_t *w)
{
    wr32be(w->b + 24, w->len);
}

/* 変換 1 つ。keylen が 0 でなければ鍵長の属性(0x800E)を付ける。 */
static void put_transform(wbuf_t *w, int last, uint8_t type, uint16_t id, uint16_t keylen)
{
    put8(w, last ? 0 : 3);
    put8(w, 0);
    put16(w, keylen ? 12 : 8);
    put8(w, type);
    put8(w, 0);
    put16(w, id);
    if (keylen) { put16(w, 0x800E); put16(w, keylen); }
}

/* SA ペイロード(提案 1 つ)。IKE なら ENCR / PRF / DH、ESP なら ENCR / ESN と SPI 4 バイト。 */
static void put_sa(wbuf_t *w, uint8_t propnum, uint8_t proto, uint32_t esp_spi)
{
    uint8_t *h = pl_begin(w, PL_SA);
    uint8_t *ph = w->b + w->len;
    put8(w, 0);           /* 最後の提案 */
    put8(w, 0);
    put16(w, 0);          /* 長さは後で */
    put8(w, propnum);
    put8(w, proto);
    if (proto == PROTO_IKE) {
        put8(w, 0);       /* SPI の長さ */
        put8(w, 3);
        put_transform(w, 0, TR_ENCR, ENCR_AES_GCM_16, 128);
        put_transform(w, 0, TR_PRF, PRF_HMAC_SHA2_256, 0);
        put_transform(w, 1, TR_DH, DH_CURVE25519, 0);
    } else {
        put8(w, 4);
        put8(w, 2);
        put32(w, esp_spi);
        put_transform(w, 0, TR_ENCR, ENCR_AES_GCM_16, 128);
        put_transform(w, 1, TR_ESN, 0, 0);
    }
    wr16be(ph + 2, (uint16_t)(w->b + w->len - ph));
    pl_end(w, h);
}

static void put_notify(wbuf_t *w, uint8_t proto, uint16_t type, const void *data, uint32_t dlen)
{
    uint8_t *h = pl_begin(w, PL_NOTIFY);
    put8(w, proto);
    put8(w, 0);
    put16(w, type);
    if (dlen) put(w, data, dlen);
    pl_end(w, h);
}

/* ID_IPV4_ADDR(種類 1)。本体(種類 | 予約 3 | アドレス)を id_body へも写す。 */
static void put_id(wbuf_t *w, uint8_t type, uint32_t ip, uint8_t id_body[8])
{
    uint8_t *h = pl_begin(w, type);
    id_body[0] = 1;
    id_body[1] = id_body[2] = id_body[3] = 0;
    wr32be(id_body + 4, ip);
    put(w, id_body, 8);
    pl_end(w, h);
}

/* 通信の選択子: その相手のアドレス 1 つ、プロトコル・ポートは全部。 */
static void put_ts(wbuf_t *w, uint8_t type, uint32_t ip)
{
    uint8_t *h = pl_begin(w, type);
    put8(w, 1);
    put8(w, 0); put8(w, 0); put8(w, 0);
    put8(w, 7);           /* TS_IPV4_ADDR_RANGE */
    put8(w, 0);           /* すべてのプロトコル */
    put16(w, 16);
    put16(w, 0);
    put16(w, 0xFFFF);
    put32(w, ip);
    put32(w, ip);
    pl_end(w, h);
}

/* 平文の内側のペイロード(inner、最初の種類は first)を SK ペイロードで包んで w の後ろへ足す。
 * 鍵は送る側のもの(始めた側なら SK_ei)。AAD は IKE のヘッダから SK のヘッダまで(RFC 5282)。 */
static int seal_sk(wbuf_t *w, const ike_peer_t *p, int as_initiator, uint8_t first,
                   const uint8_t *inner, uint32_t ilen)
{
    uint8_t *h = pl_begin(w, PL_SK);
    if (!h) return -1;
    h[0] = first;          /* SK の「次のペイロード」は中の最初のペイロード */
    w->np = h;             /* SK の後ろには何も続かないが、念のため */
    const uint32_t ctlen = ilen + 1u;   /* パディング 0 + Pad Length 1 */
    if (w->len + 8u + ctlen + 16u > w->cap) return -1;
    uint8_t *iv = w->b + w->len;
    crypto_random(iv, 8);
    uint8_t *ct = iv + 8;
    memcpy(ct, inner, ilen);
    ct[ilen] = 0;
    w->len += 8u + ctlen + 16u;
    h[0] = first;
    wr16be(h + 2, (uint16_t)(w->b + w->len - h));
    hdr_finish(w);
    w->b[16] = PL_SK;   /* ヘッダの次は SK だけ */
    uint8_t nonce[12];
    memcpy(nonce, as_initiator ? p->salt_i : p->salt_r, 4);
    memcpy(nonce + 4, iv, 8);
    crypto_aes128gcm_seal(as_initiator ? &p->k_i : &p->k_r, nonce, w->b, (size_t)(h + 4 - w->b),
                          ct, ctlen, ct, ct + ctlen);
    return 0;
}

/* ---------------------------------------------------------------- 送受信 */

static int send_msg(ike_peer_t *p, const uint8_t *m, uint32_t len)
{
    if (!p->mac_known) {
        netaddr_t a = netaddr_v4(p->peer);
        if (net_resolve_mac(&a, p->peer_mac) != 0) return -1;
        p->mac_known = 1;
    }
    if (p->nif) netif_activate(p->nif);
    uint8_t ip[4];
    wr32be(ip, p->peer);
    p->n_tx++;
    return udp_send(ip, p->peer_mac, IKE_PORT, IKE_PORT, m, (uint16_t)len);
}

/* 応答を送り、再送に備えて控える。 */
static void send_resp(ike_peer_t *p, const uint8_t *m, uint32_t len, uint32_t msgid)
{
    if (len <= sizeof(p->last_resp)) {
        memcpy(p->last_resp, m, len);
        p->last_resp_len = len;
        p->last_resp_msgid = msgid;
    }
    send_msg(p, m, len);
}

static void send_req(ike_peer_t *p, const uint8_t *m, uint32_t len)
{
    if (len <= sizeof(p->last_req)) {
        memcpy(p->last_req, m, len);
        p->last_req_len = len;
    }
    p->got_resp = 0;
    send_msg(p, m, len);
}

/* ペイロードの並びをたどる。 */
typedef struct {
    const uint8_t *sa, *ke, *nonce, *idi, *idr, *auth, *tsi, *tsr, *sk;
    uint32_t sa_len, ke_len, nonce_len, idi_len, idr_len, auth_len, tsi_len, tsr_len, sk_len;
    uint8_t sk_first;
    int transport;
    uint16_t notify_err;
    const uint8_t *del[4];
    uint32_t del_len[4];
    unsigned ndel;
} parsed_t;

static int parse_payloads(uint8_t first, const uint8_t *b, uint32_t len, parsed_t *o)
{
    uint8_t np = first;
    uint32_t off = 0;
    while (np != PL_NONE) {
        if (off + 4u > len) return -1;
        const uint8_t next = b[off];
        const uint32_t plen = rd16be(b + off + 2);
        if (plen < 4u || off + plen > len) return -1;
        const uint8_t *body = b + off + 4;
        const uint32_t blen = plen - 4u;
        switch (np) {
        case PL_SA: o->sa = body; o->sa_len = blen; break;
        case PL_KE: o->ke = body; o->ke_len = blen; break;
        case PL_NONCE: o->nonce = body; o->nonce_len = blen; break;
        case PL_IDI: o->idi = body; o->idi_len = blen; break;
        case PL_IDR: o->idr = body; o->idr_len = blen; break;
        case PL_AUTH: o->auth = body; o->auth_len = blen; break;
        case PL_TSI: o->tsi = body; o->tsi_len = blen; break;
        case PL_TSR: o->tsr = body; o->tsr_len = blen; break;
        case PL_SK: o->sk = body; o->sk_len = blen; o->sk_first = next; return 0;   /* SK は最後 */
        case PL_DELETE:
            if (o->ndel < 4) { o->del[o->ndel] = body; o->del_len[o->ndel] = blen; o->ndel++; }
            break;
        case PL_NOTIFY:
            if (blen >= 4) {
                const uint16_t t = rd16be(body + 2);
                if (t == N_USE_TRANSPORT_MODE) o->transport = 1;
                else if (t < 16384u && !o->notify_err) o->notify_err = t;   /* 誤りの通知 */
            }
            break;
        default:
            if (b[off + 1] & 0x80u) return -2;   /* 知らない重要(critical)なペイロード */
            break;
        }
        np = next;
        off += plen;
    }
    return 0;
}

/* SA ペイロードから、こちらの組(proto により IKE / ESP)を含む提案を探す。
 * 見つかれば提案番号(ESP なら相手の SPI も)を返す。0 = 無い。 */
static uint8_t pick_proposal(const uint8_t *sa, uint32_t len, uint8_t proto, uint32_t *spi)
{
    uint32_t off = 0;
    while (off + 8u <= len) {
        const uint8_t last = sa[off];
        const uint32_t plen = rd16be(sa + off + 2);
        if (plen < 8u || off + plen > len) return 0;
        const uint8_t num = sa[off + 4], pr = sa[off + 5], spisz = sa[off + 6], nt = sa[off + 7];
        const uint8_t *t = sa + off + 8 + spisz;
        uint32_t toff = 0, tlen = plen - 8u - spisz;
        int encr = 0, prfok = 0, dh = 0, esn_no = 0, esn_any = 0, bad = 0, integ = 0, dh_any = 0;
        for (unsigned i = 0; i < nt && toff + 8u <= tlen; i++) {
            const uint32_t tl = rd16be(t + toff + 2);
            if (tl < 8u || toff + tl > tlen) { bad = 1; break; }
            const uint8_t type = t[toff + 4];
            const uint16_t id = rd16be(t + toff + 6);
            uint16_t keylen = 0;
            for (uint32_t a = 8; a + 4u <= tl; ) {
                const uint16_t at = rd16be(t + toff + a);
                if (at & 0x8000u) {
                    if ((at & 0x7FFFu) == 14u) keylen = rd16be(t + toff + a + 2);
                    a += 4;
                } else {
                    a += 4u + rd16be(t + toff + a + 2);
                }
            }
            if (type == TR_ENCR && id == ENCR_AES_GCM_16 && keylen == 128) encr = 1;
            else if (type == TR_PRF && id == PRF_HMAC_SHA2_256) prfok = 1;
            else if (type == TR_DH) { dh_any = 1; if (id == DH_CURVE25519) dh = 1; else if (id == 0) dh = dh ? dh : 2; }
            else if (type == TR_ESN) { esn_any = 1; if (id == 0) esn_no = 1; }
            else if (type == TR_INTEG && id != 0) integ = 1;
            toff += tl;
        }
        (void)integ;
        if (!bad && pr == proto) {
            if (proto == PROTO_IKE && encr && prfok && dh == 1) return num;
            if (proto == PROTO_ESP && encr && (esn_no || !esn_any) && (!dh_any || dh == 2) && spisz == 4) {
                *spi = rd32be(sa + off + 8);
                return num;
            }
        }
        if (last == 0) break;
        off += plen;
    }
    return 0;
}

/* SK ペイロードを開く。in はメッセージ全体(AAD のため)、sk は SK の本体。平文の位置と長さを返す。 */
static int open_sk(const ike_peer_t *p, int from_initiator, uint8_t *msg, const uint8_t *sk, uint32_t sk_len,
                   uint8_t **pt, uint32_t *ptlen)
{
    if (sk_len < 8u + 1u + 16u) return -1;
    uint8_t *iv = (uint8_t *)(uintptr_t)sk;
    uint8_t *ct = iv + 8;
    const uint32_t ctlen = sk_len - 8u - 16u;
    uint8_t nonce[12];
    memcpy(nonce, from_initiator ? p->salt_i : p->salt_r, 4);
    memcpy(nonce + 4, iv, 8);
    if (crypto_aes128gcm_open(from_initiator ? &p->k_i : &p->k_r, nonce, msg, (size_t)(sk - msg),
                              ct, ctlen, ct, ct + ctlen) != 0)
        return -1;
    const uint8_t padlen = ct[ctlen - 1];
    if ((uint32_t)padlen + 1u > ctlen) return -1;
    *pt = ct;
    *ptlen = ctlen - 1u - padlen;
    return 0;
}

static void install_child(ike_peer_t *p)
{
    uint8_t k_i2r[KEY_LEN], k_r2i[KEY_LEN];
    derive_child_keys(p, k_i2r, k_r2i);
    if (p->initiator) ipsec_sa_install(p->peer, p->esp_spi_in, k_r2i, p->esp_spi_out, k_i2r);
    else ipsec_sa_install(p->peer, p->esp_spi_in, k_i2r, p->esp_spi_out, k_r2i);
    crypto_wipe(k_i2r, sizeof(k_i2r));
    crypto_wipe(k_r2i, sizeof(k_r2i));
    p->state = ST_ESTABLISHED;
    p->n_up++;
    uart_printf("[ike] %u.%u.%u.%u と SA を確立(%s、ESP SPI 受 0x%08x / 送 0x%08x)\n", p->peer >> 24,
                (p->peer >> 16) & 255u, (p->peer >> 8) & 255u, p->peer & 255u,
                p->initiator ? "こちらから" : "相手から", p->esp_spi_in, p->esp_spi_out);
}

static uint32_t self_ip(const ike_peer_t *p)
{
    return p->nif ? p->nif->ip : net_active_ip();
}

static void reset_sa(ike_peer_t *p)
{
    ipsec_sa_del(p->peer);
    p->state = ST_NONE;
    p->ni_len = p->nr_len = 0;
    p->msg1_len = p->msg2_len = 0;
    p->last_resp_len = p->last_req_len = 0;
    memset(p->spi_i, 0, 8);
    memset(p->spi_r, 0, 8);
    p->my_msgid = p->peer_msgid = 0;
}

/* ---------------------------------------------------------------- 受ける側 */

/* IKE_SA_INIT の要求に答える。 */
static void r_sa_init(ike_peer_t *p, uint8_t *m, uint32_t len, const parsed_t *q)
{
    static uint8_t out[MSG_MAX];
    uint32_t dummy;
    const uint8_t num = q->sa ? pick_proposal(q->sa, q->sa_len, PROTO_IKE, &dummy) : 0;
    reset_sa(p);
    memcpy(p->spi_i, m, 8);
    crypto_random(p->spi_r, 8);
    wbuf_t w;
    if (!num || !q->ke || !q->nonce || q->nonce_len < 16 || q->nonce_len > 256) {
        memset(p->spi_r, 0, 8);
        hdr_init(&w, out, sizeof(out), p, EX_IKE_SA_INIT, F_RESPONSE, 0);
        put_notify(&w, 0, N_NO_PROPOSAL_CHOSEN, NULL, 0);
        hdr_finish(&w);
        send_msg(p, out, w.len);
        uart_printf("[ike] IKE_SA_INIT: 受けられる提案が無い(AES-GCM-16-128 / PRF-SHA256 / X25519 が要る)\n");
        return;
    }
    if (q->ke_len != 4u + 32u || rd16be(q->ke) != DH_CURVE25519) {
        /* 相手の KE が別の群。X25519 で送り直すよう求める(2.7)。 */
        uint8_t g[2];
        wr16be(g, DH_CURVE25519);
        memset(p->spi_r, 0, 8);
        hdr_init(&w, out, sizeof(out), p, EX_IKE_SA_INIT, F_RESPONSE, 0);
        put_notify(&w, 0, N_INVALID_KE_PAYLOAD, g, 2);
        hdr_finish(&w);
        send_msg(p, out, w.len);
        return;
    }
    memcpy(p->ni, q->nonce, q->nonce_len);
    p->ni_len = q->nonce_len;
    crypto_random(p->nr, NONCE_LEN);
    p->nr_len = NONCE_LEN;
    crypto_x25519_keygen(p->x_priv, p->x_pub);
    hdr_init(&w, out, sizeof(out), p, EX_IKE_SA_INIT, F_RESPONSE, 0);
    put_sa(&w, num, PROTO_IKE, 0);
    uint8_t *h = pl_begin(&w, PL_KE);
    put16(&w, DH_CURVE25519);
    put16(&w, 0);
    put(&w, p->x_pub, 32);
    pl_end(&w, h);
    h = pl_begin(&w, PL_NONCE);
    put(&w, p->nr, NONCE_LEN);
    pl_end(&w, h);
    hdr_finish(&w);
    memcpy(p->msg1, m, len);
    p->msg1_len = len;
    memcpy(p->msg2, out, w.len);
    p->msg2_len = w.len;
    if (derive_ike_keys(p, q->ke + 4) != 0) { reset_sa(p); return; }
    p->initiator = 0;
    p->state = ST_R_INIT;
    p->peer_msgid = 1;
    send_resp(p, out, w.len, 0);
}

/* IKE_AUTH の要求(復号済みの中身)に答える。 */
static void r_auth(ike_peer_t *p, const uint8_t *pt, uint32_t ptlen, uint8_t first, uint32_t msgid)
{
    static uint8_t out[MSG_MAX];
    static uint8_t inner[1024];
    parsed_t q;
    memset(&q, 0, sizeof(q));
    wbuf_t w, iw;
    uint8_t dummy_np = 0;
    iw.b = inner; iw.cap = sizeof(inner); iw.len = 0; iw.np = &dummy_np;
    int ok = parse_payloads(first, pt, ptlen, &q) == 0 && q.idi && q.auth && q.sa && q.tsi && q.tsr;
    uint8_t want[PRF_LEN];
    if (ok) {
        compute_auth(p, 1, q.idi, q.idi_len, want);
        ok = q.auth_len == 4u + PRF_LEN && q.auth[0] == 2 && crypto_equal(q.auth + 4, want, PRF_LEN);
        if (!ok) uart_printf("[ike] IKE_AUTH: 相手の AUTH が合わない(事前共有鍵か身元が違う)\n");
    }
    if (!ok) {
        put_notify(&iw, 0, N_AUTH_FAILED, NULL, 0);
        hdr_init(&w, out, sizeof(out), p, EX_IKE_AUTH, F_RESPONSE, msgid);
        seal_sk(&w, p, 0, PL_NOTIFY, inner, iw.len);
        send_resp(p, out, w.len, msgid);
        reset_sa(p);
        return;
    }
    uint32_t peer_spi = 0;
    const uint8_t num = pick_proposal(q.sa, q.sa_len, PROTO_ESP, &peer_spi);
    if (!num || !q.transport) {
        uart_printf("[ike] IKE_AUTH: 子 SA を受けられない(ESP AES-GCM-16-128 の提案%s が要る)\n",
                    q.transport ? "" : "とトランスポートモード");
        put_notify(&iw, 0, N_NO_PROPOSAL_CHOSEN, NULL, 0);
        hdr_init(&w, out, sizeof(out), p, EX_IKE_AUTH, F_RESPONSE, msgid);
        seal_sk(&w, p, 0, PL_NOTIFY, inner, iw.len);
        send_resp(p, out, w.len, msgid);
        p->state = ST_ESTABLISHED;   /* IKE SA だけは成立(子は無し)*/
        return;
    }
    p->esp_spi_out = peer_spi;
    crypto_random(&p->esp_spi_in, 4);
    p->esp_spi_in |= 0x100u;
    uint8_t idr[8], auth[PRF_LEN];
    put_id(&iw, PL_IDR, self_ip(p), idr);
    compute_auth(p, 0, idr, 8, auth);
    uint8_t *h = pl_begin(&iw, PL_AUTH);
    put8(&iw, 2); put8(&iw, 0); put8(&iw, 0); put8(&iw, 0);
    put(&iw, auth, PRF_LEN);
    pl_end(&iw, h);
    put_notify(&iw, 0, N_USE_TRANSPORT_MODE, NULL, 0);
    put_sa(&iw, num, PROTO_ESP, p->esp_spi_in);
    put_ts(&iw, PL_TSI, p->peer);
    put_ts(&iw, PL_TSR, self_ip(p));
    hdr_init(&w, out, sizeof(out), p, EX_IKE_AUTH, F_RESPONSE, msgid);
    seal_sk(&w, p, 0, PL_IDR, inner, iw.len);
    install_child(p);
    send_resp(p, out, w.len, msgid);
}

/* INFORMATIONAL の要求(DELETE と生存確認)。空の(または DELETE を返す)応答を送る。 */
static void on_informational_req(ike_peer_t *p, const uint8_t *pt, uint32_t ptlen, uint8_t first, uint32_t msgid)
{
    static uint8_t out[MSG_MAX];
    parsed_t q;
    memset(&q, 0, sizeof(q));
    parse_payloads(first, pt, ptlen, &q);
    int ike_del = 0;
    for (unsigned i = 0; i < q.ndel; i++) {
        if (q.del_len[i] >= 4 && q.del[i][0] == PROTO_IKE) ike_del = 1;
        if (q.del_len[i] >= 4 && q.del[i][0] == PROTO_ESP) {
            uart_printf("[ike] 相手が子 SA を消した\n");
            ipsec_sa_del(p->peer);
        }
    }
    wbuf_t w;
    hdr_init(&w, out, sizeof(out), p, EX_INFORMATIONAL, (uint8_t)(F_RESPONSE | (p->initiator ? F_INITIATOR : 0)), msgid);
    seal_sk(&w, p, p->initiator, PL_NONE, NULL, 0);
    send_resp(p, out, w.len, msgid);
    if (ike_del) {
        uart_printf("[ike] 相手が IKE SA を消した\n");
        reset_sa(p);
    }
}

/* ---------------------------------------------------------------- 始める側 */

static int i_send_sa_init(ike_peer_t *p)
{
    static uint8_t out[MSG_MAX];
    reset_sa(p);
    crypto_random(p->spi_i, 8);
    crypto_random(p->ni, NONCE_LEN);
    p->ni_len = NONCE_LEN;
    crypto_x25519_keygen(p->x_priv, p->x_pub);
    wbuf_t w;
    hdr_init(&w, out, sizeof(out), p, EX_IKE_SA_INIT, F_INITIATOR, 0);
    put_sa(&w, 1, PROTO_IKE, 0);
    uint8_t *h = pl_begin(&w, PL_KE);
    put16(&w, DH_CURVE25519);
    put16(&w, 0);
    put(&w, p->x_pub, 32);
    pl_end(&w, h);
    h = pl_begin(&w, PL_NONCE);
    put(&w, p->ni, NONCE_LEN);
    pl_end(&w, h);
    hdr_finish(&w);
    memcpy(p->msg1, out, w.len);
    p->msg1_len = w.len;
    p->initiator = 1;
    p->state = ST_I_INIT;
    p->my_msgid = 1;
    send_req(p, out, w.len);
    return 0;
}

static void i_send_auth(ike_peer_t *p)
{
    static uint8_t out[MSG_MAX];
    static uint8_t inner[1024];
    wbuf_t w, iw;
    uint8_t dummy_np = 0;
    iw.b = inner; iw.cap = sizeof(inner); iw.len = 0; iw.np = &dummy_np;
    uint8_t idi[8], auth[PRF_LEN];
    put_id(&iw, PL_IDI, self_ip(p), idi);
    compute_auth(p, 1, idi, 8, auth);
    uint8_t *h = pl_begin(&iw, PL_AUTH);
    put8(&iw, 2); put8(&iw, 0); put8(&iw, 0); put8(&iw, 0);
    put(&iw, auth, PRF_LEN);
    pl_end(&iw, h);
    put_notify(&iw, 0, N_USE_TRANSPORT_MODE, NULL, 0);
    crypto_random(&p->esp_spi_in, 4);
    p->esp_spi_in |= 0x100u;
    put_sa(&iw, 1, PROTO_ESP, p->esp_spi_in);
    put_ts(&iw, PL_TSI, self_ip(p));
    put_ts(&iw, PL_TSR, p->peer);
    hdr_init(&w, out, sizeof(out), p, EX_IKE_AUTH, F_INITIATOR, 1);
    seal_sk(&w, p, 1, PL_IDI, inner, iw.len);
    p->state = ST_I_AUTH;
    p->my_msgid = 2;
    send_req(p, out, w.len);
}

static void i_on_sa_init_resp(ike_peer_t *p, uint8_t *m, uint32_t len, const parsed_t *q)
{
    if (q->notify_err) {
        uart_printf("[ike] IKE_SA_INIT を断られた(通知 %u)\n", q->notify_err);
        p->fail = 1;
        return;
    }
    uint32_t dummy;
    if (!q->sa || !pick_proposal(q->sa, q->sa_len, PROTO_IKE, &dummy) || !q->ke || q->ke_len != 36u ||
        rd16be(q->ke) != DH_CURVE25519 || !q->nonce || q->nonce_len < 16 || q->nonce_len > 256) {
        uart_printf("[ike] IKE_SA_INIT の応答が受けられない形\n");
        p->fail = 1;
        return;
    }
    memcpy(p->spi_r, m + 8, 8);
    memcpy(p->nr, q->nonce, q->nonce_len);
    p->nr_len = q->nonce_len;
    memcpy(p->msg2, m, len);
    p->msg2_len = len;
    if (derive_ike_keys(p, q->ke + 4) != 0) { p->fail = 1; return; }
    p->got_resp = 1;
    i_send_auth(p);
}

static void i_on_auth_resp(ike_peer_t *p, const uint8_t *pt, uint32_t ptlen, uint8_t first)
{
    parsed_t q;
    memset(&q, 0, sizeof(q));
    if (parse_payloads(first, pt, ptlen, &q) != 0) { p->fail = 1; return; }
    if (q.notify_err) {
        uart_printf("[ike] IKE_AUTH を断られた(通知 %u)\n", q.notify_err);
        p->fail = 1;
        return;
    }
    uint8_t want[PRF_LEN];
    if (!q.idr || !q.auth) { p->fail = 1; return; }
    compute_auth(p, 0, q.idr, q.idr_len, want);
    if (q.auth_len != 4u + PRF_LEN || q.auth[0] != 2 || !crypto_equal(q.auth + 4, want, PRF_LEN)) {
        uart_printf("[ike] IKE_AUTH: 相手の AUTH が合わない\n");
        p->fail = 1;
        return;
    }
    uint32_t spi = 0;
    if (!q.sa || !pick_proposal(q.sa, q.sa_len, PROTO_ESP, &spi) || !q.transport) {
        uart_printf("[ike] IKE_AUTH: 子 SA の応答が受けられない(トランスポートモード %s)\n", q.transport ? "あり" : "なし");
        p->fail = 1;
        return;
    }
    p->esp_spi_out = spi;
    p->got_resp = 1;
    install_child(p);
}

/* ---------------------------------------------------------------- 受信の入口 */

static void ike_rx(const uint8_t *data, size_t len, const netaddr_t *src, uint16_t src_port, const uint8_t *src_mac)
{
    (void)src_port;
    if (src->family != NETADDR_V4 || len < HDR_LEN || len > MSG_MAX) return;
    ike_peer_t *p = find_peer(netaddr_v4_host(src));
    if (!p) return;
    static uint8_t m[MSG_MAX];   /* 復号のため写す(受信バッファは const)*/
    memcpy(m, data, len);
    p->n_rx++;
    if (src_mac && !p->mac_known) { memcpy(p->peer_mac, src_mac, 6); p->mac_known = 1; }
    if (!p->nif) p->nif = g_active_ctx;
    if (m[17] != 0x20 || rd32be(m + 24) != len) { p->n_bad++; return; }
    const uint8_t ex = m[18], fl = m[19];
    const uint32_t msgid = rd32be(m + 20);
    const int resp = (fl & F_RESPONSE) != 0;
    parsed_t q;
    memset(&q, 0, sizeof(q));
    if (parse_payloads(m[16], m + HDR_LEN, (uint32_t)len - HDR_LEN, &q) < 0) { p->n_bad++; return; }

    if (ex == EX_IKE_SA_INIT) {
        if (!resp && (fl & F_INITIATOR)) {
            if (p->state == ST_R_INIT && memcmp(p->spi_i, m, 8) == 0 && p->last_resp_len) {
                send_msg(p, p->last_resp, p->last_resp_len);   /* 再送への答え直し */
                return;
            }
            r_sa_init(p, m, (uint32_t)len, &q);
        } else if (resp && p->state == ST_I_INIT && memcmp(p->spi_i, m, 8) == 0) {
            i_on_sa_init_resp(p, m, (uint32_t)len, &q);
        }
        return;
    }
    /* ここから先は確立した(しつつある)IKE SA の上。SPI と SK が要る。 */
    if (memcmp(p->spi_i, m, 8) != 0 || memcmp(p->spi_r, m + 8, 8) != 0 || !q.sk) { p->n_bad++; return; }
    if (!resp) {
        if (msgid + 1u == p->peer_msgid && p->last_resp_len && p->last_resp_msgid == msgid) {
            send_msg(p, p->last_resp, p->last_resp_len);   /* 相手の再送 */
            return;
        }
        if (msgid != p->peer_msgid) { p->n_bad++; return; }
    } else if (msgid + 1u != p->my_msgid) {
        p->n_bad++;
        return;
    }
    const int from_initiator = (fl & F_INITIATOR) != 0;
    uint8_t *pt;
    uint32_t ptlen;
    if (open_sk(p, from_initiator, m, q.sk, q.sk_len, &pt, &ptlen) != 0) {
        uart_printf("[ike] SK を開けない(鍵が違う)\n");
        p->n_bad++;
        return;
    }
    if (!resp) {
        p->peer_msgid = msgid + 1u;
        if (ex == EX_IKE_AUTH && p->state == ST_R_INIT) r_auth(p, pt, ptlen, q.sk_first, msgid);
        else if (ex == EX_INFORMATIONAL) on_informational_req(p, pt, ptlen, q.sk_first, msgid);
        else {
            /* 作り直しなどは受けない。 */
            static uint8_t out[MSG_MAX];
            static uint8_t inner[64];
            wbuf_t w, iw;
            uint8_t dnp = 0;
            iw.b = inner; iw.cap = sizeof(inner); iw.len = 0; iw.np = &dnp;
            put_notify(&iw, 0, N_NO_ADDITIONAL_SAS, NULL, 0);
            hdr_init(&w, out, sizeof(out), p, ex, (uint8_t)(F_RESPONSE | (p->initiator ? F_INITIATOR : 0)), msgid);
            seal_sk(&w, p, p->initiator, PL_NOTIFY, inner, iw.len);
            send_resp(p, out, w.len, msgid);
        }
        return;
    }
    if (ex == EX_IKE_AUTH && p->state == ST_I_AUTH) i_on_auth_resp(p, pt, ptlen, q.sk_first);
    else if (ex == EX_INFORMATIONAL) p->got_resp = 1;
}

/* ---------------------------------------------------------------- 公開 */

int ike_init(void)
{
    if (s_bound) return 0;
    if (udp_bind(IKE_PORT, ike_rx) < 0) return -1;
    s_bound = 1;
    return 0;
}

int ike_peer_add(uint32_t ip, const char *psk, netif_t *nif, const uint8_t mac[6])
{
    if (ike_init() < 0) return -1;
    ike_peer_t *p = find_peer(ip);
    if (!p) {
        for (unsigned i = 0; i < IKE_PEERS && !p; i++)
            if (!s_ike[i].used) p = &s_ike[i];
        if (!p) return -1;
        memset(p, 0, sizeof(*p));
    }
    const size_t l = strlen(psk);
    if (l == 0 || l >= sizeof(p->psk)) return -1;
    memcpy(p->psk, psk, l + 1);
    p->psklen = (uint32_t)l;
    p->peer = ip;
    p->nif = nif;
    if (mac) { memcpy(p->peer_mac, mac, 6); p->mac_known = 1; }
    p->used = 1;
    return ipsec_policy_add(ip);
}

void ike_peer_del(uint32_t ip)
{
    ike_peer_t *p = find_peer(ip);
    if (p) {
        reset_sa(p);
        crypto_wipe(p, sizeof(*p));
    }
    ipsec_policy_del(ip);
}

/* 応答を待つ(同期)。1 秒ごとに要求を送り直し、5 回で諦める。 */
static int wait_resp(ike_peer_t *p, uint8_t want_state)
{
    uint64_t t0 = timer_now();
    unsigned tries = 0;
    while (!p->fail && p->state != want_state && p->state != ST_ESTABLISHED) {
        job_scheduler_tick();
        net_poll_all_and_dispatch();
        if (timeout_ms(t0, 1000u)) {
            if (++tries >= 5) return -1;
            send_msg(p, p->last_req, p->last_req_len);
            t0 = timer_now();
        }
    }
    return p->fail ? -1 : 0;
}

int ike_up(uint32_t ip)
{
    ike_peer_t *p = find_peer(ip);
    if (!p) return -1;
    p->fail = 0;
    if (p->nif) netif_activate(p->nif);
    i_send_sa_init(p);
    if (wait_resp(p, ST_I_AUTH) < 0) {
        uart_printf("[ike] IKE_SA_INIT の応答が来ない / 失敗\n");
        reset_sa(p);
        return -1;
    }
    if (wait_resp(p, ST_ESTABLISHED) < 0 || p->state != ST_ESTABLISHED) {
        uart_printf("[ike] IKE_AUTH の応答が来ない / 失敗\n");
        reset_sa(p);
        return -1;
    }
    return 0;
}

void ike_down(uint32_t ip)
{
    ike_peer_t *p = find_peer(ip);
    if (!p || p->state != ST_ESTABLISHED) {
        if (p) reset_sa(p);
        return;
    }
    static uint8_t out[MSG_MAX];
    static uint8_t inner[32];
    wbuf_t w, iw;
    uint8_t dnp = 0;
    iw.b = inner; iw.cap = sizeof(inner); iw.len = 0; iw.np = &dnp;
    uint8_t *h = pl_begin(&iw, PL_DELETE);
    put8(&iw, PROTO_IKE); put8(&iw, 0); put16(&iw, 0);   /* IKE SA ごと(子も一緒に消える)*/
    pl_end(&iw, h);
    hdr_init(&w, out, sizeof(out), p, EX_INFORMATIONAL, p->initiator ? F_INITIATOR : 0, p->my_msgid);
    seal_sk(&w, p, p->initiator, PL_DELETE, inner, iw.len);
    p->my_msgid++;
    p->state = ST_DELETING;
    send_req(p, out, w.len);
    uint64_t t0 = timer_now();
    while (!p->got_resp && !timeout_ms(t0, 1000u)) {
        job_scheduler_tick();
        net_poll_all_and_dispatch();
    }
    uart_printf("[ike] DELETE を送った(応答 %s)\n", p->got_resp ? "あり" : "なし");
    reset_sa(p);
}

void ike_status(void)
{
    static const char *const ST[] = { "なし", "INIT 送信済み", "AUTH 送信済み", "確立", "INIT 応答済み", "削除中" };
    for (unsigned i = 0; i < IKE_PEERS; i++) {
        ike_peer_t *p = &s_ike[i];
        if (!p->used) continue;
        uart_printf("ike: %u.%u.%u.%u  状態 %s(%s)  確立 %u 回、受 %u / 送 %u、捨てた %u\n", p->peer >> 24,
                    (p->peer >> 16) & 255u, (p->peer >> 8) & 255u, p->peer & 255u, ST[p->state],
                    p->initiator ? "こちらから" : "相手から", p->n_up, p->n_rx, p->n_tx, p->n_bad);
    }
    ipsec_status();
}
