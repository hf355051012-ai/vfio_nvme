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
#include <stddef.h>
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
#define PRF_HMAC_SHA2_384 6u
#define DH_CURVE25519     31u
#define KE_MLKEM1024      37u     /* draft-ietf-ipsecme-ikev2-mlkem(IANA: 35/36/37 = ML-KEM-512/768/1024)*/
#define PROTO_IKE 1u
#define PROTO_ESP 3u
/* 通知 */
#define N_UNSUPPORTED_CRITICAL_PAYLOAD 1u
#define N_INVALID_MAJOR_VERSION        5u
#define N_INVALID_SYNTAX               7u
#define N_NO_PROPOSAL_CHOSEN          14u
#define N_INVALID_KE_PAYLOAD          17u
#define N_AUTH_FAILED                 24u
#define N_NO_ADDITIONAL_SAS           35u
#define N_TS_UNACCEPTABLE             38u
#define N_COOKIE                   16390u
#define N_USE_TRANSPORT_MODE       16391u

#define HDR_LEN   28u
#define NONCE_LEN 32u
#define PRF_MAX   48u      /* SHA-384 */
#define KEY_MAX   36u      /* AES-256 の鍵 32 + salt 4 */
#define KE_MAX    CRYPTO_MLKEM1024_CT_LEN   /* ML-KEM-1024 のカプセル化鍵 / 暗号文(どちらも 1568)*/
#define MSG_MAX   4096u    /* ML-KEM の KE(1568)を載せた IKE_SA_INIT が 1.7KB 前後になる */
#define IKE_PEERS 4u
#define COOKIE_MAX 64u     /* RFC 7296 2.6: COOKIE の中身は 1〜64 バイト */
#define COOKIE_TRIES 3u    /* COOKIE を求められて送り直す上限(応答者が求め続けて回り続けないため)*/
/* 再送(RFC 7296 2.4 の MUST: 間隔を指数で延ばす)。1・2・4 秒待って送り直し、最後に 8 秒待つ(計 15 秒)。 */
#define RETX_BASE_MS 1000u
#define RETX_MAX     3u

/* 交わす組(相手ごと。`ipsec psk ... cnsa` で CNSA 2.0 の組)。
 *   既定:     IKE aes128gcm16-prfsha256-x25519、ESP aes128gcm16
 *   CNSA 2.0: IKE aes256gcm16-prfsha384-mlkem1024、ESP aes256gcm16(PLAN_cnsa2.md 段階 3) */
typedef struct {
    uint16_t encr_bits;   /* AES-GCM の鍵長(IKE / ESP 共通)*/
    uint16_t prf_id;      /* PRF の変換 ID */
    uint16_t ke_id;       /* 鍵交換の変換 ID(DH 群 / ML-KEM)*/
    crypto_hash_id_t hid; /* PRF のハッシュ */
} ike_suite_t;
static const ike_suite_t SUITE_DEFAULT = { 128u, PRF_HMAC_SHA2_256, DH_CURVE25519, CRYPTO_SHA256 };
static const ike_suite_t SUITE_CNSA    = { 256u, PRF_HMAC_SHA2_384, KE_MLKEM1024, CRYPTO_SHA384 };

enum { ST_NONE = 0, ST_I_INIT, ST_I_AUTH, ST_ESTABLISHED, ST_R_INIT, ST_DELETING };

/*=================================================================
 * IKE SA 1 つぶん(と、その相手の設定)。
 *
 * **相手ごとに 2 つ持つ: 確立した SA(s_ike[])と、交渉中の SA(s_half[])。**
 * IKE_SA_INIT は認証されていない(誰でも相手のアドレスを騙って送れる)ので、
 * 新しい交換は必ず s_half[] で進め、IKE_AUTH で相手を認証できてから s_ike[] と
 * 置き換える(promote())。以前は 1 つしか持たず、IKE_SA_INIT を受けた時点で
 * 確立済みの IKE SA と ESP の SA を消していたので、**偽の IKE_SA_INIT 1 個で
 * 動いている IPsec を止められた**(RFC 7296 2.21.1 / 2.6: 認証されていない
 * メッセージで状態を壊さない)。半開きは相手ごとに 1 つだけ(新しい IKE_SA_INIT は
 * 前の半開きを捨てる)。確立済みの SA は守られるが、交渉そのものは邪魔されうる。
 * ===============================================================*/
typedef struct {
    uint8_t  used;
    uint32_t peer;
    netif_t *nif;
    uint8_t  peer_mac[6];
    uint8_t  mac_known;
    char     psk[128];
    uint32_t psklen;
    ike_suite_t suite;
    uint32_t prf_len;                 /* PRF の出力長(32 / 48)*/
    uint32_t key_len;                 /* AES の鍵長 + salt 4(20 / 36)*/
    uint32_t self_test;               /* 試験用: こちらのアドレスの差し替え(0 = しない)*/
    /* ---- ここから下が IKE SA の状態(sa_clear() が消す)---- */
    uint8_t  state, initiator;
    uint8_t  spi_i[8], spi_r[8];
    uint8_t  ni[256], nr[256];
    uint32_t ni_len, nr_len;
    uint8_t  x_priv[32];
    uint8_t  ke_mine[KE_MAX];         /* こちらの KE の中身(X25519 の公開値 / ML-KEM のカプセル化鍵か暗号文)*/
    uint32_t ke_mine_len;
    uint8_t  ml_dk[CRYPTO_MLKEM1024_DK_LEN];   /* 始めた側の ML-KEM の復号鍵(応答を受けるまで)*/
    uint8_t  sk_d[PRF_MAX], sk_pi[PRF_MAX], sk_pr[PRF_MAX];
    uint8_t  salt_i[4], salt_r[4];
    crypto_aesgcm_t k_i, k_r;      /* SK_ei / SK_er */
    uint8_t  msg1[MSG_MAX], msg2[MSG_MAX];   /* IKE_SA_INIT の要求と応答(AUTH の計算に使う)*/
    uint32_t msg1_len, msg2_len;
    uint32_t my_msgid;                /* こちらの次の要求の Message ID */
    uint32_t peer_msgid;              /* 相手の次の要求の Message ID */
    uint8_t  last_resp[MSG_MAX];      /* 相手の要求の再送に答え直すため */
    uint32_t last_resp_len, last_resp_msgid;
    uint8_t  last_req[MSG_MAX];       /* こちらの要求の再送 */
    uint32_t last_req_len;
    uint32_t req_gen;                 /* 新しい要求を送るたびに進む(待つ側が再送の間隔を最初に戻す)*/
    uint8_t  got_resp;                /* こちらの要求への応答が来た */
    uint32_t esp_spi_in, esp_spi_out;
    uint8_t  child_up;                /* 子 SA(ESP)を入れた */
    uint8_t  fail;
    uint16_t last_notify;             /* 最後に受けた誤りの通知(始めた側の報告と試験用)*/
    uint8_t  cookie[COOKIE_MAX];      /* 始めた側: 応答者に求められた COOKIE(RFC 7296 2.6)*/
    uint32_t cookie_len;
    uint8_t  cookie_tries;
} ike_peer_t;

/* 統計(確立した SA と交渉中の SA で共通。置き換えても消えない)。 */
typedef struct {
    uint32_t n_up, n_rx, n_tx, n_bad, n_retx, n_crit, n_err;
} ike_stat_t;

static ike_peer_t s_ike[IKE_PEERS];
static ike_peer_t s_half[IKE_PEERS];
static ike_stat_t s_stat[IKE_PEERS];
static int s_bound;

/* 試験用(rfctest sec)。説明は ike.h。 */
static int s_test_loop;
static uint32_t s_test_rto_ms;
static uint8_t s_test_ts_proto;
static ike_test_filter_fn s_test_filter;

static ike_peer_t *find_peer(uint32_t ip)
{
    for (unsigned i = 0; i < IKE_PEERS; i++)
        if (s_ike[i].used && s_ike[i].peer == ip) return &s_ike[i];
    return NULL;
}

static unsigned slot_of(const ike_peer_t *p)
{
    return (p >= s_half && p < s_half + IKE_PEERS) ? (unsigned)(p - s_half) : (unsigned)(p - s_ike);
}

static ike_stat_t *ST(const ike_peer_t *p) { return &s_stat[slot_of(p)]; }
static ike_peer_t *half_of(const ike_peer_t *main) { return &s_half[slot_of(main)]; }
static ike_peer_t *main_of(const ike_peer_t *p) { return &s_ike[slot_of(p)]; }

/* ---------------------------------------------------------------- 鍵 */

static void set_suite(ike_peer_t *p, const ike_suite_t *s)
{
    p->suite = *s;
    p->prf_len = (uint32_t)crypto_hash_len(s->hid);
    p->key_len = s->encr_bits / 8u + 4u;
}

static void prf(const ike_peer_t *p, const void *k, size_t kl, const void *m, size_t ml, uint8_t *out)
{
    crypto_hmac(p->suite.hid, k, kl, m, ml, out);
}

/* prf+(RFC 7296 2.13)。T1 = prf(K, S | 0x01)、Tn = prf(K, Tn-1 | S | n)。 */
static void prf_plus(const ike_peer_t *p, const void *k, size_t kl, const uint8_t *s, size_t sl,
                     uint8_t *out, size_t olen)
{
    uint8_t t[PRF_MAX];
    size_t tl = 0, done = 0;
    for (uint8_t n = 1; done < olen; n++) {
        crypto_hmac_ctx_t c;
        crypto_hmac_init(&c, p->suite.hid, k, kl);
        crypto_hmac_update(&c, t, tl);
        crypto_hmac_update(&c, s, sl);
        crypto_hmac_update(&c, &n, 1);
        crypto_hmac_final(&c, t);
        tl = p->prf_len;
        const size_t take = (olen - done < tl) ? olen - done : tl;
        memcpy(out + done, t, take);
        done += take;
    }
    crypto_wipe(t, sizeof(t));
}

/* Nonce の長さの下限(RFC 7296 2.10): 128 ビット以上、かつ PRF の鍵長の半分以上。
 * HMAC-SHA2 の PRF の鍵長は出力長と同じ(RFC 4868)なので、SHA-256 なら 16、SHA-384 なら 24 バイト。
 * CNSA の組で 16 バイトの Nonce を受けると、SKEYSEED の鍵の強さが 192 ビットに届かない。 */
static uint32_t nonce_min(const ike_peer_t *p)
{
    return p->prf_len / 2u > 16u ? p->prf_len / 2u : 16u;
}

/* ---- 鍵交換(X25519 か ML-KEM-1024)----
 * ML-KEM は KEM なので向きで中身が違う(draft-ietf-ipsecme-ikev2-mlkem): 始めた側の KE がカプセル化鍵、
 * 受けた側の KE がそれでカプセル化した暗号文。共有秘密はどちらも 32 バイトで、g^ir の代わりに使う。 */

/* 始めた側: こちらの KE を作る。 */
static int ke_initiator_make(ike_peer_t *p)
{
    if (p->suite.ke_id == KE_MLKEM1024) {
        p->ke_mine_len = CRYPTO_MLKEM1024_EK_LEN;
        return crypto_mlkem1024_keygen(p->ke_mine, p->ml_dk);
    }
    p->ke_mine_len = 32u;
    return crypto_x25519_keygen(p->x_priv, p->ke_mine);
}

/* 受けた側: 相手の KE から共有秘密とこちらの KE を作る。相手の KE が不正なら -1。 */
static int ke_responder(ike_peer_t *p, const uint8_t *peer, uint32_t len, uint8_t shared[32])
{
    if (p->suite.ke_id == KE_MLKEM1024) {
        if (len != CRYPTO_MLKEM1024_EK_LEN) return -1;
        p->ke_mine_len = CRYPTO_MLKEM1024_CT_LEN;
        return crypto_mlkem1024_encaps(peer, p->ke_mine, shared);   /* 係数が q 以上の ek は -1 */
    }
    if (len != 32u) return -1;
    p->ke_mine_len = 32u;
    crypto_x25519_keygen(p->x_priv, p->ke_mine);
    const int r = crypto_x25519(shared, p->x_priv, peer);
    crypto_wipe(p->x_priv, sizeof(p->x_priv));
    return r;
}

/* 始めた側: 相手の KE から共有秘密を作る。ML-KEM の暗号文が壊れていても失敗は返らず(暗黙の拒否)、
 * 違う鍵になって相手の AUTH / SK が開けない形で出る。
 * **秘密鍵は成功したときだけ消す。** IKE_SA_INIT の応答は認証されていないので、偽の応答
 * (小位数の点など)で秘密鍵を消すと、後から届く本物の応答を処理できなくなる(B7)。 */
static int ke_initiator_finish(ike_peer_t *p, const uint8_t *peer, uint32_t len, uint8_t shared[32])
{
    int r;
    if (p->suite.ke_id == KE_MLKEM1024) {
        r = (len == CRYPTO_MLKEM1024_CT_LEN) ? crypto_mlkem1024_decaps(p->ml_dk, peer, shared) : -1;
        if (r == 0) crypto_wipe(p->ml_dk, sizeof(p->ml_dk));
    } else {
        r = (len == 32u) ? crypto_x25519(shared, p->x_priv, peer) : -1;
        if (r == 0) crypto_wipe(p->x_priv, sizeof(p->x_priv));
    }
    return r;
}

/* 相手の KE の中身の長さ(向きで決まる)。 */
static uint32_t ke_peer_len(const ike_peer_t *p, int from_initiator)
{
    if (p->suite.ke_id != KE_MLKEM1024) return 32u;
    return from_initiator ? CRYPTO_MLKEM1024_EK_LEN : CRYPTO_MLKEM1024_CT_LEN;
}

/* IKE SA の鍵(2.14): SKEYSEED = prf(Ni | Nr, g^ir)、
 * SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr = prf+(SKEYSEED, Ni | Nr | SPIi | SPIr)。
 * AEAD なので SK_ai / SK_ar は 0 バイト。SK_d / SK_pi / SK_pr は PRF の長さ、SK_e は鍵 + salt 4。 */
static void derive_ike_keys(ike_peer_t *p, const uint8_t shared[32])
{
    const uint32_t pl = p->prf_len, kl = p->key_len, ak = kl - 4u;
    uint8_t seed[PRF_MAX];
    uint8_t nn[512];
    memcpy(nn, p->ni, p->ni_len);
    memcpy(nn + p->ni_len, p->nr, p->nr_len);
    prf(p, nn, p->ni_len + p->nr_len, shared, 32, seed);
    uint8_t s[512 + 16];
    memcpy(s, nn, p->ni_len + p->nr_len);
    memcpy(s + p->ni_len + p->nr_len, p->spi_i, 8);
    memcpy(s + p->ni_len + p->nr_len + 8, p->spi_r, 8);
    uint8_t km[PRF_MAX + 2 * KEY_MAX + 2 * PRF_MAX];
    prf_plus(p, seed, pl, s, p->ni_len + p->nr_len + 16, km, pl + 2u * kl + 2u * pl);
    memcpy(p->sk_d, km, pl);
    crypto_aesgcm_init(&p->k_i, km + pl, ak);
    memcpy(p->salt_i, km + pl + ak, 4);
    crypto_aesgcm_init(&p->k_r, km + pl + kl, ak);
    memcpy(p->salt_r, km + pl + kl + ak, 4);
    memcpy(p->sk_pi, km + pl + 2u * kl, pl);
    memcpy(p->sk_pr, km + pl + 2u * kl + pl, pl);
    crypto_wipe(seed, sizeof(seed));
    crypto_wipe(km, sizeof(km));
}

/* 子 SA の鍵(2.17): KEYMAT = prf+(SK_d, Ni | Nr)。始めた側から受けた側への向きの鍵が先。 */
static void derive_child_keys(ike_peer_t *p, uint8_t *k_i2r, uint8_t *k_r2i)
{
    uint8_t nn[512], km[2 * KEY_MAX];
    memcpy(nn, p->ni, p->ni_len);
    memcpy(nn + p->ni_len, p->nr, p->nr_len);
    prf_plus(p, p->sk_d, p->prf_len, nn, p->ni_len + p->nr_len, km, 2u * p->key_len);
    memcpy(k_i2r, km, p->key_len);
    memcpy(k_r2i, km + p->key_len, p->key_len);
    crypto_wipe(km, sizeof(km));
}

/* AUTH(2.15、事前共有鍵): prf(prf(鍵, "Key Pad for IKEv2"), 署名する並び)。
 * 署名する並び = 自分の IKE_SA_INIT のメッセージ | 相手の Nonce | prf(SK_p, ID の本体)。
 * COOKIE を求められたときの「自分の IKE_SA_INIT」は、COOKIE を付けて送り直したほう(応答を
 * 引き出した要求)。msg1 はそれを控えている。 */
static void compute_auth(const ike_peer_t *p, int of_initiator, const uint8_t *id_body, uint32_t id_len,
                         uint8_t *out)
{
    uint8_t kpad[PRF_MAX], mid[PRF_MAX];
    prf(p, p->psk, p->psklen, "Key Pad for IKEv2", 17, kpad);
    prf(p, of_initiator ? p->sk_pi : p->sk_pr, p->prf_len, id_body, id_len, mid);
    crypto_hmac_ctx_t c;
    crypto_hmac_init(&c, p->suite.hid, kpad, p->prf_len);
    if (of_initiator) {
        crypto_hmac_update(&c, p->msg1, p->msg1_len);
        crypto_hmac_update(&c, p->nr, p->nr_len);
    } else {
        crypto_hmac_update(&c, p->msg2, p->msg2_len);
        crypto_hmac_update(&c, p->ni, p->ni_len);
    }
    crypto_hmac_update(&c, mid, p->prf_len);
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

static void inner_init(wbuf_t *iw, uint8_t *buf, uint32_t cap, uint8_t *dnp)
{
    iw->b = buf;
    iw->cap = cap;
    iw->len = 0;
    *dnp = 0;
    iw->np = dnp;
}

/* ヘッダ(SPI は spi_i / spi_r。版は常に 2.0 で送る)。 */
static void hdr_init_spi(wbuf_t *w, uint8_t *buf, uint32_t cap, const uint8_t *spi_i, const uint8_t *spi_r,
                         uint8_t ex, uint8_t flags, uint32_t msgid)
{
    w->b = buf;
    w->cap = cap;
    memcpy(buf, spi_i, 8);
    memcpy(buf + 8, spi_r, 8);
    buf[16] = PL_NONE;
    buf[17] = 0x20;   /* 版 2.0 */
    buf[18] = ex;
    buf[19] = flags;
    wr32be(buf + 20, msgid);
    w->len = HDR_LEN;
    w->np = buf + 16;
}

static void hdr_init(wbuf_t *w, uint8_t *buf, uint32_t cap, const ike_peer_t *p, uint8_t ex,
                     uint8_t flags, uint32_t msgid)
{
    hdr_init_spi(w, buf, cap, p->spi_i, p->spi_r, ex, flags, msgid);
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

/* SA ペイロード(提案 1 つ)。IKE なら ENCR / PRF / KE(DH 群 / ML-KEM)、ESP なら ENCR / ESN と SPI 4 バイト。
 * 組は相手ごとの p->suite。 */
static void put_sa(wbuf_t *w, const ike_peer_t *p, uint8_t propnum, uint8_t proto, uint32_t esp_spi)
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
        put_transform(w, 0, TR_ENCR, ENCR_AES_GCM_16, p->suite.encr_bits);
        put_transform(w, 0, TR_PRF, p->suite.prf_id, 0);
        put_transform(w, 1, TR_DH, p->suite.ke_id, 0);
    } else {
        put8(w, 4);
        put8(w, 2);
        put32(w, esp_spi);
        put_transform(w, 0, TR_ENCR, ENCR_AES_GCM_16, p->suite.encr_bits);
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

/* 通信の選択子: その相手のアドレス 1 つ、ポートは全部。proto は 0(全部)。 */
static void put_ts(wbuf_t *w, uint8_t type, uint32_t ip, uint8_t proto)
{
    uint8_t *h = pl_begin(w, type);
    put8(w, 1);
    put8(w, 0); put8(w, 0); put8(w, 0);
    put8(w, 7);           /* TS_IPV4_ADDR_RANGE */
    put8(w, proto);
    put16(w, 16);
    put16(w, 0);
    put16(w, 0xFFFF);
    put32(w, ip);
    put32(w, ip);
    pl_end(w, h);
}

/* AUTH ペイロード(方式 2 = 事前共有鍵)。 */
static void put_auth(wbuf_t *w, const uint8_t *auth, uint32_t len)
{
    uint8_t *h = pl_begin(w, PL_AUTH);
    put8(w, 2); put8(w, 0); put8(w, 0); put8(w, 0);
    put(w, auth, len);
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
    if (ilen) memcpy(ct, inner, ilen);
    ct[ilen] = 0;
    w->len += 8u + ctlen + 16u;
    h[0] = first;
    wr16be(h + 2, (uint16_t)(w->b + w->len - h));
    hdr_finish(w);
    w->b[16] = PL_SK;   /* ヘッダの次は SK だけ */
    uint8_t nonce[12];
    memcpy(nonce, as_initiator ? p->salt_i : p->salt_r, 4);
    memcpy(nonce + 4, iv, 8);
    crypto_aesgcm_seal(as_initiator ? &p->k_i : &p->k_r, nonce, w->b, (size_t)(h + 4 - w->b),
                          ct, ctlen, ct, ct + ctlen);
    return 0;
}

/* ---------------------------------------------------------------- 送受信 */

/* 試験用の折り返し(s_test_loop): 送るものをワイヤに出さず待ち行列へ積む。 */
typedef struct {
    uint32_t src, dst, len;
    uint8_t  b[MSG_MAX];
} tq_ent_t;
#define TQ_N 8u
static tq_ent_t s_tq[TQ_N];
static unsigned s_tq_head, s_tq_n;

static uint32_t self_ip(const ike_peer_t *p)
{
    if (p->self_test) return p->self_test;
    return p->nif ? p->nif->ip : net_active_ip();
}

static int send_msg(ike_peer_t *p, const uint8_t *m, uint32_t len)
{
    ST(p)->n_tx++;
    if (s_test_loop) {
        if (s_tq_n >= TQ_N || len > MSG_MAX) return -1;
        tq_ent_t *e = &s_tq[(s_tq_head + s_tq_n) % TQ_N];
        e->src = self_ip(p);
        e->dst = p->peer;
        e->len = len;
        memcpy(e->b, m, len);
        s_tq_n++;
        return 0;
    }
    if (!p->mac_known) {
        netaddr_t a = netaddr_v4(p->peer);
        if (net_resolve_mac(&a, p->peer_mac) != 0) return -1;
        p->mac_known = 1;
    }
    if (p->nif) netif_activate(p->nif);
    uint8_t ip[4];
    wr32be(ip, p->peer);
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
    p->req_gen++;
    send_msg(p, m, len);
}

/* ペイロードの並びをたどる。 */
typedef struct {
    const uint8_t *sa, *ke, *nonce, *idi, *idr, *auth, *tsi, *tsr, *sk;
    uint32_t sa_len, ke_len, nonce_len, idi_len, idr_len, auth_len, tsi_len, tsr_len, sk_len;
    uint8_t sk_first;
    uint8_t crit_type;          /* 知らない重要なペイロードの種類(戻り値 -2 のとき)*/
    int transport;
    uint16_t notify_err;
    const uint8_t *cookie;      /* COOKIE の通知の中身 */
    uint32_t cookie_len;
    const uint8_t *del[4];
    uint32_t del_len[4];
    unsigned ndel;
} parsed_t;

/* 戻り値: 0 = 読めた、-1 = 長さが壊れている、-2 = 知らない重要なペイロード(o->crit_type)。 */
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
            if (blen >= 4u) {
                const uint16_t t = rd16be(body + 2);
                const uint32_t spisz = body[1];
                if (4u + spisz > blen) return -1;
                if (t == N_USE_TRANSPORT_MODE) o->transport = 1;
                else if (t == N_COOKIE) { o->cookie = body + 4 + spisz; o->cookie_len = blen - 4u - spisz; }
                else if (t < 16384u && !o->notify_err) o->notify_err = t;   /* 誤りの通知 */
            } else {
                return -1;
            }
            break;
        default:
            /* 知らない種類で重要(critical)の印があればメッセージごと断る(RFC 7296 2.5)。
             * 知っている種類の印は無視する(同じく 2.5)。 */
            if (b[off + 1] & 0x80u) { o->crit_type = np; return -2; }
            break;
        }
        np = next;
        off += plen;
    }
    return 0;
}

/*=================================================================
 * SA ペイロードから、こちらの組(p->suite。proto により IKE / ESP)を選べる提案を探す。
 * 見つかれば提案番号(ESP なら相手の SPI も)を返す。0 = 無い。
 *
 * 提案は「変換の種類ごとに 1 つ選ぶ」の組み合わせ(RFC 7296 3.3)。受けてよいのは:
 *   - **知らない変換の種類を含まない**(3.3.6: 分からない種類を含む提案は受けられないものとして
 *     扱う。RFC 9370 の追加の鍵交換(種類 6〜12)もこれに当たる)。
 *   - ENCR に AES-GCM-16 の決まった鍵長、IKE なら PRF と KE(こちらの群)、ESP なら KE は無いか NONE、
 *     ESN は無いか「ESN 無し」。
 *   - **INTEG は無いか、NONE(0)を含む**。GCM は結合モードなので INTEG を NONE にするしかなく
 *     (RFC 5282 / 7296 3.3)、NONE 以外の INTEG だけが並ぶ提案から GCM を選ぶと、INTEG を選ばない
 *     組を返すことになり提案に無い組み合わせになる。以前は INTEG を見ずに選んでいた。
 *   - 知らない属性の付いた変換は選ばない(3.3.6)。鍵長の属性(14)だけを知っている。
 * ===============================================================*/
static uint8_t pick_proposal(const ike_peer_t *p, const uint8_t *sa, uint32_t len, uint8_t proto, uint32_t *spi)
{
    uint32_t off = 0;
    while (off + 8u <= len) {
        const uint8_t last = sa[off];
        const uint32_t plen = rd16be(sa + off + 2);
        if (plen < 8u || off + plen > len) return 0;
        const uint8_t num = sa[off + 4], pr = sa[off + 5], spisz = sa[off + 6], nt = sa[off + 7];
        int bad = (8u + spisz > plen);
        const uint8_t *t = sa + off + 8 + spisz;
        const uint32_t tlen = bad ? 0u : plen - 8u - spisz;
        uint32_t toff = 0;
        int encr = 0, prfok = 0, ke_ok = 0, ke_none = 0, ke_any = 0, esn_no = 0, esn_any = 0;
        int integ_any = 0, integ_none = 0, unknown = 0;
        unsigned i;
        for (i = 0; !bad && i < nt; i++) {
            if (toff + 8u > tlen) { bad = 1; break; }
            const uint32_t tl = rd16be(t + toff + 2);
            if (tl < 8u || toff + tl > tlen) { bad = 1; break; }
            const uint8_t type = t[toff + 4];
            const uint16_t id = rd16be(t + toff + 6);
            uint16_t keylen = 0;
            int attr_bad = 0;
            for (uint32_t a = 8; a < tl; ) {
                if (a + 4u > tl) { bad = 1; break; }
                const uint16_t at = rd16be(t + toff + a);
                if (at & 0x8000u) {
                    if ((at & 0x7FFFu) == 14u) keylen = rd16be(t + toff + a + 2);
                    else attr_bad = 1;
                    a += 4;
                } else {
                    attr_bad = 1;   /* 長さ付きの属性は知らない */
                    a += 4u + rd16be(t + toff + a + 2);
                    if (a > tl) { bad = 1; break; }
                }
            }
            switch (type) {
            case TR_ENCR:
                if (!attr_bad && id == ENCR_AES_GCM_16 && keylen == p->suite.encr_bits) encr = 1;
                break;
            case TR_PRF:
                if (!attr_bad && id == p->suite.prf_id) prfok = 1;
                break;
            case TR_INTEG:
                integ_any = 1;
                if (!attr_bad && id == 0) integ_none = 1;
                break;
            case TR_DH:
                ke_any = 1;
                if (!attr_bad && id == p->suite.ke_id) ke_ok = 1;
                if (!attr_bad && id == 0) ke_none = 1;
                break;
            case TR_ESN:
                esn_any = 1;
                if (!attr_bad && id == 0) esn_no = 1;
                break;
            default:
                unknown = 1;
                break;
            }
            toff += tl;
        }
        if (!bad && (i != nt || toff != tlen)) bad = 1;   /* 変換の数と長さが合わない */
        if (!bad && !unknown && pr == proto && (!integ_any || integ_none)) {
            if (proto == PROTO_IKE && encr && prfok && ke_ok) return num;
            if (proto == PROTO_ESP && encr && (esn_no || !esn_any) && (!ke_any || ke_none) && spisz == 4) {
                *spi = rd32be(sa + off + 8);
                return num;
            }
        }
        if (last == 0) break;
        off += plen;
    }
    return 0;
}

/*=================================================================
 * Traffic Selector(RFC 7296 2.9 / 3.13)を確かめる。
 *
 * この実装の方針は「相手のアドレスとの間の IPv4 は全部 ESP」(ipsec.c)なので、子 SA の
 * TS は**ホスト間・全プロトコル・全ポート**でなければならない。それより狭い TS で合意すると、
 * 合意の外の通信まで同じ SA で包み、相手はそれを方針違反として捨てる。
 *   - 受けた側(within = 0): 相手の提案のどれかが ip を含み、プロトコル 0・ポート 0〜65535 なら可。
 *     こちらの応答は ip 1 つだけに狭める(2.9: 応答者は狭めてよい)。
 *   - 始めた側(within = 1): 応答の TS は、こちらが出した範囲(ip 1 つ)に収まっていなければならず
 *     (応答者は広げてはいけない)、かつ全プロトコル・全ポートの ip を含むこと。
 * 含まなければ受けた側は TS_UNACCEPTABLE(3.10.1)、始めた側は子 SA を使わない。
 * ===============================================================*/
static int ts_ok(const uint8_t *ts, uint32_t len, uint32_t ip, int within)
{
    if (!ts || len < 4u) return 0;
    const unsigned n = ts[0];
    uint32_t off = 4;
    int full = 0;
    for (unsigned i = 0; i < n; i++) {
        if (off + 4u > len) return 0;
        const uint8_t type = ts[off], proto = ts[off + 1];
        const uint32_t tl = rd16be(ts + off + 2);
        if (tl < 8u || off + tl > len) return 0;
        if (type == 7u && tl == 16u) {
            const uint16_t sp = rd16be(ts + off + 4), ep = rd16be(ts + off + 6);
            const uint32_t sa = rd32be(ts + off + 8), ea = rd32be(ts + off + 12);
            if (sa <= ip && ip <= ea && proto == 0 && sp == 0 && ep == 0xFFFFu) full = 1;
            if (within && (sa != ip || ea != ip)) return 0;
        } else if (within) {
            return 0;   /* こちらが出していない種類(IPv6 など)で答えてきた */
        }
        off += tl;
    }
    return full;
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
    if (crypto_aesgcm_open(from_initiator ? &p->k_i : &p->k_r, nonce, msg, (size_t)(sk - msg),
                              ct, ctlen, ct, ct + ctlen) != 0)
        return -1;
    const uint8_t padlen = ct[ctlen - 1];
    if ((uint32_t)padlen + 1u > ctlen) return -1;
    *pt = ct;
    *ptlen = ctlen - 1u - padlen;
    return 0;
}

/* 受信の ESP の SPI を選ぶ。**ほかの相手の受信の SPI と重ねない**(ipsec.c の受信は SPI だけで
 * SA を引くため。RFC 4301 4.1)。交渉中・確立済みの IKE SA が控えている値とも重ねない。 */
static uint32_t alloc_spi_in(const ike_peer_t *p)
{
    for (;;) {
        uint32_t spi;
        crypto_random(&spi, 4);
        spi |= 0x100u;   /* 1〜255 は予約(RFC 4303 2.1)*/
        int clash = ipsec_spi_in_used(spi, p->peer);
        for (unsigned i = 0; i < IKE_PEERS && !clash; i++) {
            if (&s_ike[i] != p && s_ike[i].used && s_ike[i].esp_spi_in == spi) clash = 1;
            if (&s_half[i] != p && s_half[i].used && s_half[i].esp_spi_in == spi) clash = 1;
        }
        if (!clash) return spi;
    }
}

static int install_child(ike_peer_t *p)
{
    uint8_t k_i2r[KEY_MAX], k_r2i[KEY_MAX];
    const size_t ak = p->key_len - 4u;
    derive_child_keys(p, k_i2r, k_r2i);
    int r;
    if (p->initiator) r = ipsec_sa_install(p->peer, p->esp_spi_in, k_r2i, p->esp_spi_out, k_i2r, ak);
    else r = ipsec_sa_install(p->peer, p->esp_spi_in, k_i2r, p->esp_spi_out, k_r2i, ak);
    crypto_wipe(k_i2r, sizeof(k_i2r));
    crypto_wipe(k_r2i, sizeof(k_r2i));
    if (r != 0) {
        uart_printf("[ike] ESP の SA を入れられない(受信の SPI 0x%08x が重なる)\n", p->esp_spi_in);
        return -1;
    }
    p->state = ST_ESTABLISHED;
    p->child_up = 1;
    ST(p)->n_up++;
    uart_printf("[ike] %u.%u.%u.%u と SA を確立(%s、IKE aes%ugcm16-prfsha%u-%s、ESP aes%ugcm16、"
                "SPI 受 0x%08x / 送 0x%08x)\n", p->peer >> 24,
                (p->peer >> 16) & 255u, (p->peer >> 8) & 255u, p->peer & 255u,
                p->initiator ? "こちらから" : "相手から", p->suite.encr_bits, p->prf_len * 8u,
                p->suite.ke_id == KE_MLKEM1024 ? "mlkem1024" : "x25519", p->suite.encr_bits,
                p->esp_spi_in, p->esp_spi_out);
    return 0;
}

/* IKE SA の状態を消す(ESP の SA には触らない。消すのは呼び出し側)。設定(相手・鍵・組)は残す。 */
static void sa_clear(ike_peer_t *p)
{
    const size_t off = offsetof(ike_peer_t, state);
    crypto_wipe((uint8_t *)p + off, sizeof(*p) - off);
    p->state = ST_NONE;
}

/* 確立した SA(s_ike[])を畳む: その IKE SA の子 SA(ESP)も消す。**ipsec.c の SA がこの IKE SA の
 * 子のときだけ**消す(受信の SPI で確かめる)。交渉中の SA が IKE_AUTH を終えて子 SA を入れ替えた
 * 直後に、相手が古い IKE SA の Delete を送ってくることがある(相手も置き換えの後始末をする)。
 * そのとき ESP の SA を無条件に消すと、入れたばかりの新しい子 SA が消える。 */
static void main_teardown(ike_peer_t *main)
{
    if (main->child_up) ipsec_sa_del_if(main->peer, main->esp_spi_in);
    sa_clear(main);
}

/* 交渉中の SA を始める: 設定を確立側から写し、状態は空にする。 */
static ike_peer_t *half_begin(ike_peer_t *main)
{
    ike_peer_t *h = half_of(main);
    crypto_wipe(h, sizeof(*h));
    const size_t off = offsetof(ike_peer_t, state);
    memcpy(h, main, off);   /* used / peer / nif / MAC / 事前共有鍵 / 組 */
    h->state = ST_NONE;
    return h;
}

/* IKE SA の Delete を 1 回だけ送る(応答は待たない。置き換える古い SA / 失敗した交渉の後始末)。 */
static void send_delete_nowait(ike_peer_t *p)
{
    static uint8_t out[MSG_MAX];
    uint8_t inner[32], dnp;
    wbuf_t w, iw;
    inner_init(&iw, inner, sizeof(inner), &dnp);
    uint8_t *h = pl_begin(&iw, PL_DELETE);
    put8(&iw, PROTO_IKE); put8(&iw, 0); put16(&iw, 0);
    pl_end(&iw, h);
    hdr_init(&w, out, sizeof(out), p, EX_INFORMATIONAL, p->initiator ? F_INITIATOR : 0, p->my_msgid);
    seal_sk(&w, p, p->initiator, PL_DELETE, inner, iw.len);
    p->my_msgid++;
    send_msg(p, out, w.len);
}

/*=================================================================
 * 交渉中の SA(IKE_AUTH で相手を認証できたもの)を確立した SA と置き換える。
 *
 * 古い IKE SA が確立していれば、その IKE SA の Delete を 1 回だけ送る(相手に残っている
 * 古い IKE SA と子 SA を畳ませる。応答は待たない)。子 SA は install_child() が ipsec.c の
 * SA を置き換え済み。子 SA を作れなかった(IKE SA だけ成立した)ときは古い ESP の SA を消す
 * (古い ESP の SA は古い IKE SA のもので、上の Delete で相手側からも消える)。
 * ===============================================================*/
static void promote(ike_peer_t *half)
{
    ike_peer_t *main = main_of(half);
    if (main->state == ST_ESTABLISHED) send_delete_nowait(main);
    if (!half->child_up && main->child_up) ipsec_sa_del_if(main->peer, main->esp_spi_in);
    memcpy(main, half, sizeof(*main));
    crypto_wipe(half, sizeof(*half));
}

/* ---------------------------------------------------------------- 誤りの応答 */

/* IKE_SA_INIT の要求 m への、暗号化しない誤りの応答(RFC 7296 2.21.1: IKE_SA_INIT の誤りは
 * 保護しない通知で返す)。SPI は要求のまま、応答者の SPI は 0。p の状態には触らない。 */
static void send_init_notify(ike_peer_t *p, const uint8_t *m, uint16_t type, const void *data, uint32_t dlen)
{
    static uint8_t out[512];
    static const uint8_t zero[8];
    wbuf_t w;
    hdr_init_spi(&w, out, sizeof(out), m, zero, EX_IKE_SA_INIT, F_RESPONSE, 0);
    put_notify(&w, 0, type, data, dlen);
    hdr_finish(&w);
    send_msg(p, out, w.len);
}

/* 保護した要求への、通知 1 つだけの保護した応答(2.21.2: 応答者の誤りは保護した応答で、
 * ふつうはその通知だけを返す)。 */
static void reply_error(ike_peer_t *p, uint8_t ex, uint32_t msgid, uint16_t type, const void *data, uint32_t dlen)
{
    static uint8_t out[MSG_MAX];
    uint8_t inner[64], dnp;
    wbuf_t w, iw;
    inner_init(&iw, inner, sizeof(inner), &dnp);
    put_notify(&iw, 0, type, data, dlen);
    hdr_init(&w, out, sizeof(out), p, ex, (uint8_t)(F_RESPONSE | (p->initiator ? F_INITIATOR : 0)), msgid);
    seal_sk(&w, p, p->initiator, PL_NOTIFY, inner, iw.len);
    send_resp(p, out, w.len, msgid);
    ST(p)->n_err++;
}

/* メジャー版が 2 より大きい要求への INVALID_MAJOR_VERSION(RFC 7296 3.1 / 2.5)。
 * メッセージは捨て、保護しない通知を返す。こちらが扱える版(2.0)はヘッダに入る。 */
static void send_invalid_major(ike_peer_t *p, const uint8_t *m)
{
    static uint8_t out[128];
    wbuf_t w;
    hdr_init_spi(&w, out, sizeof(out), m, m + 8, m[18], F_RESPONSE, rd32be(m + 20));
    put_notify(&w, 0, N_INVALID_MAJOR_VERSION, NULL, 0);
    hdr_finish(&w);
    send_msg(p, out, w.len);
}

/* ---------------------------------------------------------------- 受ける側 */

/* IKE_SA_INIT の要求に答える。p は交渉中の SA(half_begin() 済み)。 */
static void r_sa_init(ike_peer_t *p, uint8_t *m, uint32_t len, const parsed_t *q)
{
    static uint8_t out[MSG_MAX];
    uint32_t dummy;
    wbuf_t w;
    if (!q->sa || !q->ke || !q->nonce) {
        send_init_notify(p, m, N_INVALID_SYNTAX, NULL, 0);
        uart_printf("[ike] IKE_SA_INIT: SA / KE / Nonce のどれかが無い\n");
        sa_clear(p);
        return;
    }
    const uint8_t num = pick_proposal(p, q->sa, q->sa_len, PROTO_IKE, &dummy);
    if (!num) {
        send_init_notify(p, m, N_NO_PROPOSAL_CHOSEN, NULL, 0);
        uart_printf("[ike] IKE_SA_INIT: 受けられる提案が無い(AES-GCM-16-%u / PRF-SHA%u / %s が要る)\n",
                    p->suite.encr_bits, p->prf_len * 8u, p->suite.ke_id == KE_MLKEM1024 ? "ML-KEM-1024" : "X25519");
        sa_clear(p);
        return;
    }
    if (q->nonce_len < nonce_min(p) || q->nonce_len > 256u) {
        /* 2.10: 128 ビット以上・PRF の鍵長の半分以上。3.9: 256 バイト以下。 */
        send_init_notify(p, m, N_INVALID_SYNTAX, NULL, 0);
        uart_printf("[ike] IKE_SA_INIT: Nonce の長さ %u が範囲外(%u〜256)\n", q->nonce_len, nonce_min(p));
        sa_clear(p);
        return;
    }
    if (q->ke_len < 4u) {
        send_init_notify(p, m, N_INVALID_SYNTAX, NULL, 0);
        sa_clear(p);
        return;
    }
    if (rd16be(q->ke) != p->suite.ke_id) {
        /* 相手の KE が別の群。こちらの群で送り直すよう求める(2.7)。 */
        uint8_t g[2];
        wr16be(g, p->suite.ke_id);
        send_init_notify(p, m, N_INVALID_KE_PAYLOAD, g, 2);
        sa_clear(p);
        return;
    }
    if (q->ke_len != 4u + ke_peer_len(p, 1)) {
        /* **群は合っているのに長さだけ違う**: 群を変えて送り直しても直らないので INVALID_KE_PAYLOAD
         * ではなく INVALID_SYNTAX(RFC 7296 3.10.1。ML-KEM の draft も長さの違う KE を INVALID_SYNTAX で
         * 断る。strongSwan も KE の値を使えなければ IKE_SA_INIT の応答で INVALID_SYNTAX を返す)。
         * 以前は INVALID_KE_PAYLOAD で同じ群を求め直し、相手は同じものを送り続けた。 */
        send_init_notify(p, m, N_INVALID_SYNTAX, NULL, 0);
        uart_printf("[ike] IKE_SA_INIT: KE の長さ %u が群の決まりと違う\n", q->ke_len - 4u);
        sa_clear(p);
        return;
    }
    uint8_t shared[32];
    if (ke_responder(p, q->ke + 4, q->ke_len - 4u, shared) != 0) {
        /* 相手の X25519 の公開値が小位数の点 / ML-KEM のカプセル化鍵の係数が q 以上 */
        send_init_notify(p, m, N_INVALID_SYNTAX, NULL, 0);
        uart_printf("[ike] IKE_SA_INIT: 相手の KE の値が不正\n");
        crypto_wipe(shared, sizeof(shared));
        sa_clear(p);
        return;
    }
    memcpy(p->spi_i, m, 8);
    crypto_random(p->spi_r, 8);
    memcpy(p->ni, q->nonce, q->nonce_len);
    p->ni_len = q->nonce_len;
    crypto_random(p->nr, NONCE_LEN);
    p->nr_len = NONCE_LEN;
    hdr_init(&w, out, sizeof(out), p, EX_IKE_SA_INIT, F_RESPONSE, 0);
    put_sa(&w, p, num, PROTO_IKE, 0);
    uint8_t *h = pl_begin(&w, PL_KE);
    put16(&w, p->suite.ke_id);
    put16(&w, 0);
    put(&w, p->ke_mine, p->ke_mine_len);
    pl_end(&w, h);
    h = pl_begin(&w, PL_NONCE);
    put(&w, p->nr, NONCE_LEN);
    pl_end(&w, h);
    hdr_finish(&w);
    memcpy(p->msg1, m, len);
    p->msg1_len = len;
    memcpy(p->msg2, out, w.len);
    p->msg2_len = w.len;
    derive_ike_keys(p, shared);
    crypto_wipe(shared, sizeof(shared));
    p->initiator = 0;
    p->state = ST_R_INIT;
    p->peer_msgid = 1;
    send_resp(p, out, w.len, 0);
}

/* IKE_AUTH の要求(復号して読んだ中身 q)に答える。p は交渉中の SA。 */
static void r_auth(ike_peer_t *p, const parsed_t *q, uint32_t msgid)
{
    static uint8_t out[MSG_MAX];
    static uint8_t inner[1024];
    wbuf_t w, iw;
    uint8_t dnp;
    inner_init(&iw, inner, sizeof(inner), &dnp);
    /* この実装は子 SA を必ず作る(RFC 6023 の子 SA 無しは使わない)ので、5 つとも要る。
     * 欠けていれば壊れた要求として INVALID_SYNTAX(RFC 7296 3.10.1)。AUTH を確かめる前に断る。 */
    if (!q->idi || !q->auth || !q->sa || !q->tsi || !q->tsr) {
        uart_printf("[ike] IKE_AUTH: IDi / AUTH / SA / TSi / TSr のどれかが無い\n");
        reply_error(p, EX_IKE_AUTH, msgid, N_INVALID_SYNTAX, NULL, 0);
        sa_clear(p);
        return;
    }
    uint8_t want[PRF_MAX];
    compute_auth(p, 1, q->idi, q->idi_len, want);
    if (!(q->auth_len == 4u + p->prf_len && q->auth[0] == 2 && crypto_equal(q->auth + 4, want, p->prf_len))) {
        uart_printf("[ike] IKE_AUTH: 相手の AUTH が合わない(事前共有鍵か身元が違う)\n");
        reply_error(p, EX_IKE_AUTH, msgid, N_AUTH_FAILED, NULL, 0);
        sa_clear(p);
        return;
    }
    /* ここから先は相手を認証できた。IKE SA は成立する(子 SA を作れなくても。RFC 7296 2.21.2)。
     * 応答には IDr と AUTH を必ず入れる(相手がこちらを認証するため)。 */
    uint8_t idr[8], auth[PRF_MAX];
    put_id(&iw, PL_IDR, self_ip(p), idr);
    compute_auth(p, 0, idr, 8, auth);
    put_auth(&iw, auth, p->prf_len);
    uint32_t peer_spi = 0;
    const uint8_t num = pick_proposal(p, q->sa, q->sa_len, PROTO_ESP, &peer_spi);
    const int ts = ts_ok(q->tsi, q->tsi_len, p->peer, 0) && ts_ok(q->tsr, q->tsr_len, self_ip(p), 0);
    if (!num || !q->transport || !ts) {
        const uint16_t why = !num || !q->transport ? N_NO_PROPOSAL_CHOSEN : N_TS_UNACCEPTABLE;
        uart_printf("[ike] IKE_AUTH: 子 SA を受けられない(%s)\n",
                    !num ? "ESP AES-GCM-16 の提案が無い" : !q->transport ? "トランスポートモードでない"
                         : "TS がホスト間・全プロトコル・全ポートを含まない");
        put_notify(&iw, 0, why, NULL, 0);
        hdr_init(&w, out, sizeof(out), p, EX_IKE_AUTH, F_RESPONSE, msgid);
        seal_sk(&w, p, 0, PL_IDR, inner, iw.len);
        p->state = ST_ESTABLISHED;   /* IKE SA だけは成立(子は無し)*/
        p->child_up = 0;
        send_resp(p, out, w.len, msgid);
        ST(p)->n_err++;
        promote(p);
        return;
    }
    p->esp_spi_out = peer_spi;
    p->esp_spi_in = alloc_spi_in(p);
    put_notify(&iw, 0, N_USE_TRANSPORT_MODE, NULL, 0);
    put_sa(&iw, p, num, PROTO_ESP, p->esp_spi_in);
    put_ts(&iw, PL_TSI, p->peer, 0);
    put_ts(&iw, PL_TSR, self_ip(p), 0);
    hdr_init(&w, out, sizeof(out), p, EX_IKE_AUTH, F_RESPONSE, msgid);
    seal_sk(&w, p, 0, PL_IDR, inner, iw.len);
    if (install_child(p) != 0) {
        reply_error(p, EX_IKE_AUTH, msgid, N_NO_PROPOSAL_CHOSEN, NULL, 0);
        sa_clear(p);
        return;
    }
    send_resp(p, out, w.len, msgid);
    promote(p);
}

/*=================================================================
 * INFORMATIONAL の要求(Delete と生存確認)。p は確立した SA。
 *
 * Delete(RFC 7296 1.4.1 / 3.11):
 *   - IKE SA の Delete(SPI の長さ 0)は子 SA ごと畳む。応答は空。
 *   - ESP の Delete は**相手の受信の SPI**(= こちらの送信の SPI、esp_spi_out)を並べてくる。
 *     **SPI がこちらの子 SA と合うときだけ**消し、応答にこちらの受信の SPI の Delete を入れて
 *     対を閉じたことを伝える。以前は SPI を見ずに消していた(知らない SPI の Delete で
 *     動いている ESP の SA が消えた)。
 * ===============================================================*/
static void on_informational_req(ike_peer_t *p, const parsed_t *q, uint32_t msgid)
{
    static uint8_t out[MSG_MAX];
    uint8_t inner[64], dnp;
    int ike_del = 0, esp_del = 0;
    for (unsigned i = 0; i < q->ndel; i++) {
        const uint8_t *d = q->del[i];
        const uint32_t dl = q->del_len[i];
        if (dl < 4u) continue;
        if (d[0] == PROTO_IKE) {
            ike_del = 1;
        } else if (d[0] == PROTO_ESP && d[1] == 4u) {
            const uint32_t nspi = rd16be(d + 2);
            for (uint32_t k = 0; k < nspi && 4u + 4u * k + 4u <= dl; k++) {
                const uint32_t spi = rd32be(d + 4 + 4u * k);
                if (p->child_up && spi == p->esp_spi_out) esp_del = 1;
                else uart_printf("[ike] 知らない SPI 0x%08x の ESP の Delete(無視)\n", spi);
            }
        }
    }
    wbuf_t w, iw;
    inner_init(&iw, inner, sizeof(inner), &dnp);
    uint8_t first = PL_NONE;
    if (esp_del && !ike_del) {
        uint8_t *h = pl_begin(&iw, PL_DELETE);
        put8(&iw, PROTO_ESP); put8(&iw, 4); put16(&iw, 1);
        put32(&iw, p->esp_spi_in);
        pl_end(&iw, h);
        first = PL_DELETE;
        uart_printf("[ike] 相手が子 SA を消した\n");
        ipsec_sa_del_if(p->peer, p->esp_spi_in);
        p->child_up = 0;
    }
    hdr_init(&w, out, sizeof(out), p, EX_INFORMATIONAL, (uint8_t)(F_RESPONSE | (p->initiator ? F_INITIATOR : 0)), msgid);
    seal_sk(&w, p, p->initiator, first, inner, iw.len);
    send_resp(p, out, w.len, msgid);
    if (ike_del) {
        uart_printf("[ike] 相手が IKE SA を消した\n");
        main_teardown(p);
    }
}

/* ---------------------------------------------------------------- 始める側 */

/* IKE_SA_INIT の要求を組んで送る(状態は i_start() が作ったもの)。COOKIE を求められていれば
 * **最初のペイロードとして** COOKIE の通知を付け、ほかは同じにして送り直す(RFC 7296 2.6)。 */
static void i_send_sa_init(ike_peer_t *p)
{
    static uint8_t out[MSG_MAX];
    wbuf_t w;
    hdr_init(&w, out, sizeof(out), p, EX_IKE_SA_INIT, F_INITIATOR, 0);
    if (p->cookie_len) put_notify(&w, 0, N_COOKIE, p->cookie, p->cookie_len);
    put_sa(&w, p, 1, PROTO_IKE, 0);
    uint8_t *h = pl_begin(&w, PL_KE);
    put16(&w, p->suite.ke_id);
    put16(&w, 0);
    put(&w, p->ke_mine, p->ke_mine_len);
    pl_end(&w, h);
    h = pl_begin(&w, PL_NONCE);
    put(&w, p->ni, NONCE_LEN);
    pl_end(&w, h);
    hdr_finish(&w);
    memcpy(p->msg1, out, w.len);   /* AUTH が署名するのは、応答を引き出したこの要求 */
    p->msg1_len = w.len;
    send_req(p, out, w.len);
}

static int i_start(ike_peer_t *p)
{
    crypto_random(p->spi_i, 8);
    crypto_random(p->ni, NONCE_LEN);
    p->ni_len = NONCE_LEN;
    if (ke_initiator_make(p) != 0) return -1;
    p->initiator = 1;
    p->state = ST_I_INIT;
    p->my_msgid = 1;
    i_send_sa_init(p);
    return 0;
}

static void i_send_auth(ike_peer_t *p)
{
    static uint8_t out[MSG_MAX];
    static uint8_t inner[1024];
    wbuf_t w, iw;
    uint8_t dnp;
    inner_init(&iw, inner, sizeof(inner), &dnp);
    uint8_t idi[8], auth[PRF_MAX];
    put_id(&iw, PL_IDI, self_ip(p), idi);
    compute_auth(p, 1, idi, 8, auth);
    put_auth(&iw, auth, p->prf_len);
    put_notify(&iw, 0, N_USE_TRANSPORT_MODE, NULL, 0);
    p->esp_spi_in = alloc_spi_in(p);
    put_sa(&iw, p, 1, PROTO_ESP, p->esp_spi_in);
    put_ts(&iw, PL_TSI, self_ip(p), s_test_ts_proto);
    put_ts(&iw, PL_TSR, p->peer, s_test_ts_proto);
    hdr_init(&w, out, sizeof(out), p, EX_IKE_AUTH, F_INITIATOR, 1);
    seal_sk(&w, p, 1, PL_IDI, inner, iw.len);
    p->state = ST_I_AUTH;
    p->my_msgid = 2;
    send_req(p, out, w.len);
}

/*=================================================================
 * IKE_SA_INIT の応答(始めた側)。
 *
 * **この応答は認証されていない**(誰でもこちらの SPI を見て偽の応答を送れる)。
 * RFC 7296 2.21.1: 始めた側は IKE_SA_INIT への誤りの通知を受けても、すぐに諦めず、
 * 本物の応答が来るかもしれないので時間切れまで待ち続けるのがよい(SHOULD)。そこで
 *   - COOKIE(2.6 の MUST): 求められた COOKIE を最初のペイロードに付けて送り直す(上限 3 回)。
 *   - 誤りの通知 / 受けられない形 / KE の値が不正: 理由を控えて**無視して待ち続ける**
 *     (状態も秘密鍵も変えない)。時間切れのときに控えた理由を表示する。
 * 以前は誤りの通知 1 個で交渉を諦めていた(偽の NO_PROPOSAL_CHOSEN 1 個で ike_up が失敗した)。
 * ===============================================================*/
static void i_on_sa_init_resp(ike_peer_t *p, uint8_t *m, uint32_t len, const parsed_t *q)
{
    if (q->cookie) {
        if (q->cookie_len < 1u || q->cookie_len > COOKIE_MAX || p->cookie_tries >= COOKIE_TRIES) {
            ST(p)->n_bad++;
            return;
        }
        memcpy(p->cookie, q->cookie, q->cookie_len);
        p->cookie_len = q->cookie_len;
        p->cookie_tries++;
        uart_printf("[ike] IKE_SA_INIT: 相手が COOKIE(%u バイト)を求めてきた。付けて送り直す\n", q->cookie_len);
        i_send_sa_init(p);
        return;
    }
    if (q->notify_err) {
        if (p->last_notify != q->notify_err)
            uart_printf("[ike] IKE_SA_INIT に誤りの通知 %u(認証されていないので、時間切れまで本物の応答を待つ)\n",
                        q->notify_err);
        p->last_notify = q->notify_err;
        ST(p)->n_err++;
        return;
    }
    uint32_t dummy;
    if (!q->sa || !pick_proposal(p, q->sa, q->sa_len, PROTO_IKE, &dummy) || !q->ke ||
        q->ke_len != 4u + ke_peer_len(p, 0) || rd16be(q->ke) != p->suite.ke_id ||
        !q->nonce || q->nonce_len < nonce_min(p) || q->nonce_len > 256u || memcmp(m + 8, "\0\0\0\0\0\0\0\0", 8) == 0) {
        uart_printf("[ike] IKE_SA_INIT の応答が受けられない形(無視して待つ)\n");
        ST(p)->n_bad++;
        return;
    }
    uint8_t shared[32];
    if (ke_initiator_finish(p, q->ke + 4, q->ke_len - 4u, shared) != 0) {
        uart_printf("[ike] IKE_SA_INIT: 相手の KE の値が不正(無視して待つ)\n");
        crypto_wipe(shared, sizeof(shared));
        ST(p)->n_bad++;
        return;
    }
    memcpy(p->spi_r, m + 8, 8);
    memcpy(p->nr, q->nonce, q->nonce_len);
    p->nr_len = q->nonce_len;
    memcpy(p->msg2, m, len);
    p->msg2_len = len;
    derive_ike_keys(p, shared);
    crypto_wipe(shared, sizeof(shared));
    p->got_resp = 1;
    i_send_auth(p);
}

/* IKE_AUTH の応答(保護されている = 鍵を知る相手から)。誤りなら交渉は失敗。 */
static void i_on_auth_resp(ike_peer_t *p, const parsed_t *q)
{
    if (q->notify_err) {
        uart_printf("[ike] IKE_AUTH を断られた(通知 %u)\n", q->notify_err);
        p->last_notify = q->notify_err;
        p->fail = 1;
        return;
    }
    uint8_t want[PRF_MAX];
    if (!q->idr || !q->auth) { p->fail = 1; return; }
    compute_auth(p, 0, q->idr, q->idr_len, want);
    if (q->auth_len != 4u + p->prf_len || q->auth[0] != 2 || !crypto_equal(q->auth + 4, want, p->prf_len)) {
        uart_printf("[ike] IKE_AUTH: 相手の AUTH が合わない\n");
        p->fail = 1;
        return;
    }
    uint32_t spi = 0;
    if (!q->sa || !pick_proposal(p, q->sa, q->sa_len, PROTO_ESP, &spi) || !q->transport) {
        uart_printf("[ike] IKE_AUTH: 子 SA の応答が受けられない(トランスポートモード %s)\n", q->transport ? "あり" : "なし");
        p->fail = 1;
        return;
    }
    if (!ts_ok(q->tsi, q->tsi_len, self_ip(p), 1) || !ts_ok(q->tsr, q->tsr_len, p->peer, 1)) {
        /* 2.9: 応答の TS は提案に収まり、こちらの方針(ホスト間の全部)を覆うこと */
        uart_printf("[ike] IKE_AUTH: 応答の TS がホスト間・全プロトコル・全ポートでない\n");
        p->fail = 1;
        return;
    }
    p->esp_spi_out = spi;
    p->got_resp = 1;
    if (install_child(p) != 0) p->fail = 1;
}

/* ---------------------------------------------------------------- 受信の入口 */

static void ike_rx(const uint8_t *data, size_t len, const netaddr_t *src, uint16_t src_port,
                   const netaddr_t *dst, const uint8_t *src_mac)
{
    (void)src_port;
    (void)dst;
    if (src->family != NETADDR_V4 || len < HDR_LEN || len > MSG_MAX) return;
    ike_peer_t *main = find_peer(netaddr_v4_host(src));
    if (!main) return;
    ike_peer_t *half = half_of(main);
    static uint8_t m[MSG_MAX];   /* 復号のため写す(受信バッファは const)*/
    memcpy(m, data, len);
    ike_stat_t *st = ST(main);
    st->n_rx++;
    if (src_mac && !main->mac_known) { memcpy(main->peer_mac, src_mac, 6); main->mac_known = 1; }
    if (src_mac && half->used && !half->mac_known) { memcpy(half->peer_mac, src_mac, 6); half->mac_known = 1; }
    if (!main->nif) main->nif = g_active_ctx;
    const uint8_t ex = m[18], fl = m[19];
    const uint32_t msgid = rd32be(m + 20);
    const int resp = (fl & F_RESPONSE) != 0;
    /* 版(RFC 7296 3.1): **マイナー版は無視し、メジャー版が 2 なら受ける**(2.5: マイナー版が
     * 大きくても 2.0 として扱う)。メジャー版が大きい要求には INVALID_MAJOR_VERSION を返して捨てる。
     * 以前は 0x20 ちょうど以外を全部黙って捨てていた。 */
    if ((m[17] >> 4) != 2u) {
        if ((m[17] >> 4) > 2u && !resp) send_invalid_major(main, m);
        st->n_bad++;
        return;
    }
    if (rd32be(m + 24) != len) { st->n_bad++; return; }
    parsed_t q;
    memset(&q, 0, sizeof(q));
    const int prc = parse_payloads(m[16], m + HDR_LEN, (uint32_t)len - HDR_LEN, &q);

    if (ex == EX_IKE_SA_INIT) {
        if (!resp) {
            /* 要求は始めた側から(I が立つ)、Message ID 0、応答者の SPI は 0(3.1)。 */
            static const uint8_t zero[8];
            if (!(fl & F_INITIATOR) || msgid != 0 || memcmp(m + 8, zero, 8) != 0) { st->n_bad++; return; }
            if (half->used && half->state == ST_R_INIT && memcmp(half->spi_i, m, 8) == 0 && half->last_resp_len) {
                send_msg(half, half->last_resp, half->last_resp_len);   /* 再送への答え直し */
                return;
            }
            if (main->state == ST_ESTABLISHED && !main->initiator && memcmp(main->spi_i, m, 8) == 0) {
                st->n_bad++;   /* もう確立した SA の IKE_SA_INIT の再送(遅れて届いた)*/
                return;
            }
            if (half->used && (half->state == ST_I_INIT || half->state == ST_I_AUTH)) {
                /* こちらが交渉を始めている最中(ike_up() が待っている)。交渉中の枠は 1 つなので、
                 * 受けると ike_up() の交渉を壊す。相手は再送するので、こちらの交渉が終わってから受ける
                 * (同時に始めた場合は、こちらの交渉が成立すれば相手の再送は不要になる)。 */
                st->n_bad++;
                return;
            }
            if (prc == -2) {
                /* 2.5: 知らない重要なペイロードを含む要求は断り、その種類 1 バイトを入れて返す */
                send_init_notify(main, m, N_UNSUPPORTED_CRITICAL_PAYLOAD, &q.crit_type, 1);
                st->n_crit++;
                return;
            }
            if (prc < 0) { st->n_bad++; return; }
            r_sa_init(half_begin(main), m, (uint32_t)len, &q);
        } else {
            /* 応答は応答者から(I は立たない。3.1) */
            if ((fl & F_INITIATOR) || msgid != 0 || prc < 0 || !half->used || half->state != ST_I_INIT ||
                memcmp(half->spi_i, m, 8) != 0) {
                st->n_bad++;
                return;
            }
            i_on_sa_init_resp(half, m, (uint32_t)len, &q);
        }
        return;
    }
    /* ここから先は確立した(しつつある)IKE SA の上。SPI で SA を引く(確立したものが先)。 */
    ike_peer_t *p = NULL;
    if (main->state != ST_NONE && memcmp(main->spi_i, m, 8) == 0 && memcmp(main->spi_r, m + 8, 8) == 0) p = main;
    else if (half->used && half->state != ST_NONE && memcmp(half->spi_i, m, 8) == 0 &&
             memcmp(half->spi_r, m + 8, 8) == 0) p = half;
    if (!p || prc < 0 || !q.sk) { st->n_bad++; return; }
    /* I フラグは「元の始めた側が送った」印(3.1)。こちらが始めた SA なら相手のメッセージに
     * I は立たず、相手が始めた SA なら必ず立つ。合わないものは捨てる(どちらの SPI を
     * 自分が作ったかの取り違えを防ぐ)。 */
    const int from_initiator = (fl & F_INITIATOR) != 0;
    if (from_initiator == (int)p->initiator) { st->n_bad++; return; }
    if (!resp) {
        if (msgid + 1u == p->peer_msgid && p->last_resp_len && p->last_resp_msgid == msgid) {
            send_msg(p, p->last_resp, p->last_resp_len);   /* 相手の再送 */
            return;
        }
        if (msgid != p->peer_msgid) { st->n_bad++; return; }
    } else if (msgid + 1u != p->my_msgid) {
        st->n_bad++;
        return;
    }
    uint8_t *pt;
    uint32_t ptlen;
    if (open_sk(p, from_initiator, m, q.sk, q.sk_len, &pt, &ptlen) != 0) {
        uart_printf("[ike] SK を開けない(鍵が違う)\n");
        st->n_bad++;
        return;
    }
    parsed_t qi;
    memset(&qi, 0, sizeof(qi));
    const int irc = parse_payloads(q.sk_first, pt, ptlen, &qi);
    if (!resp) {
        p->peer_msgid = msgid + 1u;
        /* **中身を処理する前に**、知らない重要なペイロードと壊れた並びを断る(RFC 7296 2.5 / 2.21.2)。
         * IKE_AUTH なら AUTH を確かめる前、INFORMATIONAL なら Delete を処理する前。
         * 応答はその通知 1 つだけ。以前は INFORMATIONAL の読み取りの失敗を見ずに Delete を処理していた。 */
        if (irc == -2 || irc == -1) {
            if (irc == -2) {
                reply_error(p, ex, msgid, N_UNSUPPORTED_CRITICAL_PAYLOAD, &qi.crit_type, 1);
                st->n_crit++;
            } else {
                reply_error(p, ex, msgid, N_INVALID_SYNTAX, NULL, 0);
            }
            if (p->state == ST_R_INIT) sa_clear(p);   /* 認証の前に断った交渉は捨てる */
            return;
        }
        if (ex == EX_IKE_AUTH && p->state == ST_R_INIT) {
            r_auth(p, &qi, msgid);
        } else if (ex == EX_INFORMATIONAL && p->state == ST_ESTABLISHED) {
            on_informational_req(p, &qi, msgid);
        } else if (ex == EX_CREATE_CHILD && p->state == ST_ESTABLISHED) {
            /* 作り直しなどは受けない。 */
            reply_error(p, ex, msgid, N_NO_ADDITIONAL_SAS, NULL, 0);
        } else {
            reply_error(p, ex, msgid, N_INVALID_SYNTAX, NULL, 0);   /* 状態に合わない交換 */
        }
        return;
    }
    if (irc < 0) {
        /* 応答の中身が読めない: こちらの要求は失敗として扱う */
        if (ex == EX_IKE_AUTH && p->state == ST_I_AUTH) p->fail = 1;
        else p->got_resp = 1;
        st->n_bad++;
        return;
    }
    if (ex == EX_IKE_AUTH && p->state == ST_I_AUTH) {
        i_on_auth_resp(p, &qi);
    } else if (ex == EX_INFORMATIONAL) {
        p->last_notify = qi.notify_err;
        p->got_resp = 1;
    }
}

/* ---------------------------------------------------------------- 公開 */

int ike_init(void)
{
    if (s_bound) return 0;
    if (udp_bind(IKE_PORT, ike_rx) < 0) return -1;
    s_bound = 1;
    return 0;
}

int ike_peer_add(uint32_t ip, const char *psk, netif_t *nif, const uint8_t mac[6], int cnsa)
{
    if (ike_init() < 0) return -1;
    ike_peer_t *p = find_peer(ip);
    if (!p) {
        for (unsigned i = 0; i < IKE_PEERS && !p; i++)
            if (!s_ike[i].used) p = &s_ike[i];
        if (!p) return -1;
        memset(p, 0, sizeof(*p));
        memset(half_of(p), 0, sizeof(ike_peer_t));
        memset(ST(p), 0, sizeof(ike_stat_t));
    }
    const size_t l = strlen(psk);
    if (l == 0 || l >= sizeof(p->psk)) return -1;
    memcpy(p->psk, psk, l + 1);
    p->psklen = (uint32_t)l;
    set_suite(p, cnsa ? &SUITE_CNSA : &SUITE_DEFAULT);
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
        ipsec_sa_del(p->peer);
        crypto_wipe(half_of(p), sizeof(ike_peer_t));
        crypto_wipe(p, sizeof(*p));
    }
    ipsec_policy_del(ip);
}

/*=================================================================
 * こちらの要求への応答を待つ(同期)。done(p) が真になるか、失敗が立つまで。
 *
 * 再送の間隔は指数で延ばす(RFC 7296 2.4 の MUST: 込み合ったネットワークに再送を
 * 重ねないため)。1・2・4 秒待つたびに送り直し、最後に 8 秒待って諦める(計 15 秒)。
 * 以前は 1 秒ごとに 5 回送っていた(間隔が延びない)。
 * 待っている間に新しい要求を送った(COOKIE で送り直した / IKE_AUTH へ進んだ)ら間隔を最初に戻す。
 * ===============================================================*/
static void test_pump_if(void);

static int wait_until(ike_peer_t *p, int (*done)(const ike_peer_t *))
{
    uint32_t gen = p->req_gen, rto = s_test_rto_ms ? s_test_rto_ms : RETX_BASE_MS;
    unsigned tries = 0;
    uint64_t t0 = timer_now();
    while (!p->fail && !done(p)) {
        job_scheduler_tick();
        net_poll_all_and_dispatch();
        test_pump_if();
        if (p->req_gen != gen) {
            gen = p->req_gen;
            tries = 0;
            rto = s_test_rto_ms ? s_test_rto_ms : RETX_BASE_MS;
            t0 = timer_now();
            continue;
        }
        if (timeout_ms(t0, rto)) {
            if (tries >= RETX_MAX || !p->last_req_len) return -1;
            tries++;
            send_msg(p, p->last_req, p->last_req_len);
            ST(p)->n_retx++;
            rto *= 2u;
            t0 = timer_now();
        }
    }
    return p->fail ? -1 : 0;
}

static int done_init(const ike_peer_t *p) { return p->state == ST_I_AUTH || p->state == ST_ESTABLISHED; }
static int done_auth(const ike_peer_t *p) { return p->state == ST_ESTABLISHED; }
static int done_resp(const ike_peer_t *p) { return p->got_resp; }

int ike_up(uint32_t ip)
{
    ike_peer_t *main = find_peer(ip);
    if (!main) return -1;
    if (main->nif) netif_activate(main->nif);
    /* 交渉は s_half[] で進め、成功してから確立した SA と置き換える(失敗しても今の SA は残る)。 */
    ike_peer_t *p = half_begin(main);
    if (i_start(p) != 0) {
        sa_clear(p);
        return -1;
    }
    /* 1 回の待ちの中で IKE_SA_INIT の応答と IKE_AUTH の応答の両方を処理することがある
     * (どちらの段で失敗したかは状態で見る)。 */
    int r = wait_until(p, done_init);
    if (r == 0 && p->state != ST_ESTABLISHED) r = wait_until(p, done_auth);
    if (r < 0 || p->state != ST_ESTABLISHED) {
        if (p->state == ST_I_INIT) {
            if (p->last_notify) uart_printf("[ike] IKE_SA_INIT を断られた(通知 %u)\n", p->last_notify);
            else uart_printf("[ike] IKE_SA_INIT の応答が来ない / 失敗\n");
        } else {
            uart_printf("[ike] IKE_AUTH の応答が来ない / 失敗\n");
            /* 鍵ができているので、相手に残りうる IKE SA(子 SA を作れずに成立したもの)を畳ませる */
            if (p->state == ST_I_AUTH) send_delete_nowait(p);
        }
        sa_clear(p);
        p->used = 0;
        return -1;
    }
    promote(p);
    return 0;
}

void ike_down(uint32_t ip)
{
    ike_peer_t *p = find_peer(ip);
    if (!p) return;
    if (p->state != ST_ESTABLISHED) {
        main_teardown(p);
        return;
    }
    static uint8_t out[MSG_MAX];
    uint8_t inner[32], dnp;
    wbuf_t w, iw;
    inner_init(&iw, inner, sizeof(inner), &dnp);
    uint8_t *h = pl_begin(&iw, PL_DELETE);
    put8(&iw, PROTO_IKE); put8(&iw, 0); put16(&iw, 0);   /* IKE SA ごと(子も一緒に消える)*/
    pl_end(&iw, h);
    hdr_init(&w, out, sizeof(out), p, EX_INFORMATIONAL, p->initiator ? F_INITIATOR : 0, p->my_msgid);
    seal_sk(&w, p, p->initiator, PL_DELETE, inner, iw.len);
    p->my_msgid++;
    p->state = ST_DELETING;
    send_req(p, out, w.len);
    /* Delete も要求なので、応答が来るまで指数の間隔で送り直す(RFC 7296 2.4)。 */
    const int r = wait_until(p, done_resp);
    uart_printf("[ike] DELETE を送った(応答 %s)\n", r == 0 ? "あり" : "なし");
    main_teardown(p);
}

void ike_status(void)
{
    static const char *const ST_NAME[] = { "なし", "INIT 送信済み", "AUTH 送信済み", "確立", "INIT 応答済み", "削除中" };
    for (unsigned i = 0; i < IKE_PEERS; i++) {
        ike_peer_t *p = &s_ike[i];
        if (!p->used) continue;
        const ike_stat_t *s = &s_stat[i];
        uart_printf("ike: %u.%u.%u.%u  状態 %s(%s)  交渉中 %s  確立 %u 回、受 %u / 送 %u(再送 %u)、捨てた %u、"
                    "誤りの通知 %u、重要なペイロードで断った %u\n", p->peer >> 24,
                    (p->peer >> 16) & 255u, (p->peer >> 8) & 255u, p->peer & 255u, ST_NAME[p->state],
                    p->initiator ? "こちらから" : "相手から",
                    s_half[i].used ? ST_NAME[s_half[i].state] : "なし",
                    s->n_up, s->n_rx, s->n_tx, s->n_retx, s->n_bad, s->n_err, s->n_crit);
    }
    ipsec_status();
}

/* ---------------------------------------------------------------- 試験用(rfctest sec)*/

void ike_test_loop(int on, unsigned rto_ms)
{
    s_test_loop = on;
    s_test_rto_ms = on ? rto_ms : 0u;
    s_tq_head = s_tq_n = 0;
    if (!on) {
        s_test_filter = NULL;
        s_test_ts_proto = 0;
    }
}

void ike_test_set_filter(ike_test_filter_fn f) { s_test_filter = f; }
void ike_test_ts_proto(uint8_t proto) { s_test_ts_proto = proto; }

int ike_test_pop(uint32_t *src, uint32_t *dst, uint8_t *buf, uint32_t cap)
{
    if (!s_tq_n) return -1;
    tq_ent_t *e = &s_tq[s_tq_head];
    s_tq_head = (s_tq_head + 1u) % TQ_N;
    s_tq_n--;
    if (e->len > cap) return -1;
    if (src) *src = e->src;
    if (dst) *dst = e->dst;
    memcpy(buf, e->b, e->len);
    return (int)e->len;
}

void ike_test_rx(uint32_t src, uint32_t dst, const uint8_t *msg, uint32_t len)
{
    static const uint8_t mac[6] = { 0x02, 0, 0, 0, 0x7e, 0x57 };
    const netaddr_t s = netaddr_v4(src), d = netaddr_v4(dst);
    ike_rx(msg, len, &s, IKE_PORT, &d, mac);
}

void ike_test_pump(void)
{
    static uint8_t b[MSG_MAX];
    uint32_t src, dst;
    int n;
    for (unsigned guard = 0; guard < 64u && (n = ike_test_pop(&src, &dst, b, sizeof(b))) >= 0; guard++) {
        uint32_t len = (uint32_t)n;
        if (s_test_filter && s_test_filter(src, dst, b, &len)) continue;   /* 捨てた / 試験が差し替えた */
        ike_test_rx(src, dst, b, len);
    }
}

static void test_pump_if(void)
{
    if (s_test_loop) ike_test_pump();
}

int ike_test_set_self(uint32_t ip, uint32_t self)
{
    ike_peer_t *p = find_peer(ip);
    if (!p) return -1;
    p->self_test = self;
    return 0;
}

int ike_test_info(uint32_t ip, ike_test_info_t *o)
{
    ike_peer_t *p = find_peer(ip);
    if (!p) return -1;
    const ike_peer_t *h = half_of(p);
    const ike_stat_t *s = ST(p);
    memset(o, 0, sizeof(*o));
    o->state = p->state;
    o->half_state = h->used ? h->state : 0u;
    o->initiator = p->initiator;
    o->child_up = p->child_up;
    o->last_notify = p->last_notify;
    o->half_last_notify = h->used ? h->last_notify : 0u;
    o->esp_spi_in = p->esp_spi_in;
    o->esp_spi_out = p->esp_spi_out;
    memcpy(o->spi_i, p->spi_i, 8);
    memcpy(o->spi_r, p->spi_r, 8);
    o->n_up = s->n_up;
    o->n_bad = s->n_bad;
    o->n_retx = s->n_retx;
    o->n_crit = s->n_crit;
    o->n_err = s->n_err;
    return 0;
}

int ike_test_send_info(uint32_t ip, uint8_t first, const uint8_t *inner, uint32_t ilen)
{
    ike_peer_t *p = find_peer(ip);
    if (!p || p->state != ST_ESTABLISHED) return -1;
    static uint8_t out[MSG_MAX];
    wbuf_t w;
    hdr_init(&w, out, sizeof(out), p, EX_INFORMATIONAL, p->initiator ? F_INITIATOR : 0, p->my_msgid);
    if (seal_sk(&w, p, p->initiator, first, inner, ilen) != 0) return -1;
    p->my_msgid++;
    p->last_notify = 0;
    send_req(p, out, w.len);
    return wait_until(p, done_resp);
}
