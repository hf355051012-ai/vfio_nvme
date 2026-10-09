/* NVMe/TCP ターゲットの TLS 1.3(PLAN_auth_tls.md 段階 D / E)。仕様は nvmet_tls.h。 */
#include "nvmet_tls.h"
#include "nvmet.h"
#include "uart.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* PSK は身元の版 1 / 版 0 の 2 本(tls13_nvme_psk())。 */
static tls13_psk_t s_psk[2];
static unsigned    s_npsk;
static char        s_hostnqn[256];
static char        s_keylog_path[256];
static FILE       *s_keylog;

volatile uint32_t g_nvmet_tls_corrupt;

int nvmet_tls_enabled(void) { return s_npsk != 0; }

/* SSLKEYLOGFILE 形式で追記する。Precision の tshark に `-o tls.keylog_file:<path>` で
 * 渡すと、こちらが出した暗号文を相手側の道具で復号して読める。
 * **IO キューごとに握手するので、複数のコアから呼ばれうる**(書き出しは
 * 冷たい経路なので 1 行ずつ fprintf するだけ。行が混ざらないよう 1 回で書く)。 */
static void keylog_write(void *arg, const char *line) {
    (void)arg;
    if (!s_keylog && s_keylog_path[0]) s_keylog = fopen(s_keylog_path, "a");
    if (!s_keylog) return;
    fprintf(s_keylog, "%s\n", line);
    fflush(s_keylog);
}

void nvmet_tls_shell(const char *args) {
    char buf[512];
    strncpy(buf, args, sizeof(buf) - 1u);
    buf[sizeof(buf) - 1u] = 0;
    char *tok[4];
    unsigned nt = 0;
    char *save = 0;
    for (char *p = strtok_r(buf, " \t\r\n", &save); p && nt < 4u; p = strtok_r(0, " \t\r\n", &save)) tok[nt++] = p;

    if (nt == 2 && !strcmp(tok[0], "corrupt")) {
        g_nvmet_tls_corrupt = (uint32_t)strtoul(tok[1], NULL, 0);
        uart_printf("nvmettls: 次に送る %u 個のレコードの暗号文を 1 ビット壊す\n", g_nvmet_tls_corrupt);
        return;
    }
    if (nt == 1 && !strcmp(tok[0], "off")) {
        crypto_wipe(s_psk, sizeof(s_psk));
        s_npsk = 0;
    } else if (nt >= 2) {
        const char *why = "";
        tls13_psk_t p[2];
        if (tls13_nvme_psk(p, tok[1], tok[0], NVMET_SUBNQN, &why) < 0) {
            uart_printf("nvmettls: 鍵が使えない(%s)\n"
                        "使い方: nvmettls <hostnqn> <NVMeTLSkey-1:01:..:> [keylog <path>] / nvmettls off / "
                        "nvmettls corrupt <N>\n", why);
            return;
        }
        memcpy(s_psk, p, sizeof(p));
        crypto_wipe(p, sizeof(p));
        s_npsk = 2;
        strncpy(s_hostnqn, tok[0], sizeof(s_hostnqn) - 1u);
        s_keylog_path[0] = 0;
        if (s_keylog) {
            fclose(s_keylog);
            s_keylog = NULL;
        }
        if (nt >= 4 && !strcmp(tok[2], "keylog")) strncpy(s_keylog_path, tok[3], sizeof(s_keylog_path) - 1u);
    }
    if (!s_npsk) {
        uart_printf("nvmettls: TLS を使わない(次の接続から)\n");
    } else {
        uart_printf("nvmettls: 次の接続から TLS 1.3 を求める(ホスト %s、TLS_AES_128_GCM_SHA256、PSK + x25519)\n"
                    "  身元(版 1): %s\n  鍵の書き出し: %s\n",
                    s_hostnqn, s_psk[0].identity, s_keylog_path[0] ? s_keylog_path : "しない");
    }
}

void nvmet_tls_start(nvmet_tls_conn_t *s) {
    tls13_server_init(&s->t, s_psk, s_npsk);
    s->t.keylog = keylog_write;
    s->pendlen = 0;
    s->applen = s->apphead = 0;
    s->failed = 0;
    s->rx_records = s->tx_records = s->rx_bytes = s->tx_bytes = 0;
}

/* 1 TCP セグメントに収まるレコードの大きさ(TLS のヘッダ・内側の種別・タグで 22 バイト)。
 *
 * **TLS のレコードは全部、短経路(tcp_send_async2)だけで送る。** 長経路(LSO)と
 * 混ぜると、ホストの kTLS がこちらのレコードを復号できなくなった(EBADMSG、
 * ホスト側に "failed to send request -74")。レコード番号が nonce になるので、
 * **封をした順にワイヤへ出ないと 1 個で全部壊れる**。平文の応答 PDU が使っている
 * 実績のある経路にそろえ、1 レコード = 1 セグメントにする。 */
static uint32_t seg_cap(const tcp_conn_t *tcp) {
    uint32_t cap = tcp->snd_mss ? (uint32_t)tcp->snd_mss : 1400u;
    if (cap > TCP_ASYNC_SHORT_SLOT_BYTES) cap = TCP_ASYNC_SHORT_SLOT_BYTES;
    return cap;
}

static int send_raw(tcp_conn_t *tcp, const uint8_t *p, size_t n) {
    const uint32_t cap = seg_cap(tcp);
    while (n) {
        const uint32_t take = n < cap ? (uint32_t)n : cap;
        if (tcp_send_async2(tcp, p, (uint16_t)take, NULL, 0) < 0) return -1;
        p += take;
        n -= take;
    }
    return 0;
}

/* 溜めた送信(握手の応答 / KeyUpdate / alert)を吐く。 */
static int flush_pend(nvmet_tls_conn_t *s, tcp_conn_t *tcp, int handshake) {
    if (!s->pendlen) return 0;
    /* **握手中は同期送信(ACK まで待ち、自分で再送する)。** 非同期送信は
     * 「誰かがポーリングして再送を回す」前提で、握手中のイニシエータの
     * 接続ジョブはそれを回さない。実機で ClientHello が最初の 1 回でワイヤに
     * 出ず、相手が 10 秒で諦めて FIN を送ってくるまで再送されなかった
     * (ICReq が同期送信なのと同じ理由。冷たい経路なので費用は問題にならない)。 */
    if (handshake) {
        const int r = tcp_send(tcp, s->pend, (uint32_t)s->pendlen);
        const int ok = (r == (int)s->pendlen);
        s->pendlen = 0;
        return ok ? 0 : -1;
    }
    const int r = send_raw(tcp, s->pend, s->pendlen);
    s->pendlen = 0;
    return r;
}

/* 暗号文を食わせる。平文は app[applen..] へ、送るものは pend へ溜まる。 */
static int feed_raw(nvmet_tls_conn_t *s, const uint8_t *raw, size_t n) {
    size_t ol = s->pendlen;
    const uint64_t rx0 = s->t.rx.seq;
    const int rc = tls13_input(&s->t, raw, n, s->pend, sizeof(s->pend), &ol,
                               s->app, sizeof(s->app), &s->applen);
    s->pendlen = ol;
    s->rx_records += s->t.rx.seq - rx0;
    if (rc != 0) s->failed = 1;
    return rc;
}

static void log_failure(const nvmet_tls_conn_t *s) {
    if (s->t.alert_sent != 0xFF)
        uart_printf("[!] nvmet-tls: %s(alert %s を送った)\n", s->t.why ? s->t.why : "?",
                    tls13_alert_name(s->t.alert_sent));
    else if (s->t.alert_recv != 0xFF)
        uart_printf("[!] nvmet-tls: 相手が alert %s を送ってきた\n", tls13_alert_name(s->t.alert_recv));
}

int nvmet_tls_poll(nvmet_tls_conn_t *s, tcp_conn_t *tcp) {
    const tls13_state_t before = s->t.state;
    const int n = tcp_recv_no_ack(tcp, s->in, sizeof(s->in), 0u);
    if (n == 0) {
        uart_printf("[!] nvmet-tls: 握手の途中で相手が閉じた(%s)\n",
                    s->t.alert_recv != 0xFF ? tls13_alert_name(s->t.alert_recv) : "alert なし");
        return -1;
    }
    if (n < 0) return s->t.state == TLS13_ST_OPEN ? 1 : 0;
    const int rc = feed_raw(s, s->in, (size_t)n);
    if (flush_pend(s, tcp, 1) != 0) return -1;
    if (rc != 0) {
        log_failure(s);
        return -1;
    }
    if (before == TLS13_ST_WAIT_CH && s->t.state != TLS13_ST_WAIT_CH) {
        uart_printf("[nvmet-tls] ClientHello を受理(身元 %.60s...)\n", s->t.psks[s->t.psk_index].identity);
    }
    if (before != TLS13_ST_OPEN && s->t.state == TLS13_ST_OPEN) {
        uart_printf("[%s] 握手が済んだ(TLS 1.3、TLS_AES_128_GCM_SHA256、x25519、身元の版 %d)\n",
                    s->t.is_client ? "nvme-tls" : "nvmet-tls", s->t.psk_index == 0 ? 1 : 0);
    }
    return s->t.state == TLS13_ST_OPEN ? 1 : 0;
}

int nvmet_tls_recv(nvmet_tls_conn_t *s, tcp_conn_t *tcp, uint8_t *dst, uint32_t max) {
    if (s->apphead == s->applen) {
        if (s->failed || s->t.state != TLS13_ST_OPEN) return -1;
        s->apphead = s->applen = 0;
        const int n = tcp_recv_no_ack(tcp, s->in, sizeof(s->in), 0u);
        if (n == 0) return -1;
        if (n < 0) return 0;
        const int rc = feed_raw(s, s->in, (size_t)n);
        flush_pend(s, tcp, 0);
        if (rc != 0) {
            log_failure(s);
            return -1;
        }
        if (s->applen == 0) return s->t.state == TLS13_ST_CLOSED ? -1 : 0;
    }
    uint32_t take = (uint32_t)(s->applen - s->apphead);
    if (take > max) take = max;
    memcpy(dst, s->app + s->apphead, take);
    s->apphead += take;
    s->rx_bytes += take;
    return (int)take;
}

int nvmet_tls_feed(nvmet_tls_conn_t *s, const volatile uint8_t *data, uint16_t len,
                   nvmet_tls_deliver_fn deliver, void *arg) {
    const uint8_t *p = (const uint8_t *)(uintptr_t)data;
    size_t left = len;
    while (left && !s->failed) {
        const size_t take = left < NVMET_TLS_FEED ? left : NVMET_TLS_FEED;
        s->applen = s->apphead = 0;
        if (feed_raw(s, p, take) != 0) {
            log_failure(s);
            return -1;
        }
        p += take;
        left -= take;
        /* **タグの検証が通った平文だけ**がここに来る(tls13_input はレコード単位で
         * 検証してから平文を出す)。名前空間へ書くのはこの先のパーサ。 */
        for (size_t off = 0; off < s->applen;) {
            const size_t n = (s->applen - off) < 65535u ? (s->applen - off) : 65535u;
            deliver(arg, (const volatile uint8_t *)(s->app + off), (uint16_t)n);
            off += n;
        }
        s->rx_bytes += s->applen;
        s->applen = 0;
    }
    return s->failed ? -1 : 0;
}

void nvmet_tls_drain(nvmet_tls_conn_t *s, nvmet_tls_deliver_fn deliver, void *arg) {
    while (s->apphead < s->applen) {
        const size_t n = (s->applen - s->apphead) < 65535u ? (s->applen - s->apphead) : 65535u;
        deliver(arg, (const volatile uint8_t *)(s->app + s->apphead), (uint16_t)n);
        s->apphead += n;
        s->rx_bytes += n;
    }
    s->apphead = s->applen = 0;
}

int nvmet_tls_send(nvmet_tls_conn_t *s, tcp_conn_t *tcp, const void *p1, uint32_t l1,
                   const void *p2, uint32_t l2) {
    if (s->failed || s->t.state != TLS13_ST_OPEN) return -1;
    if (flush_pend(s, tcp, 0) != 0) return -1;   /* **受信中に生まれた送信を先に**(順序を崩さない)*/
    const uint8_t *f[2] = { (const uint8_t *)p1, (const uint8_t *)p2 };
    uint32_t fl[2] = { l1, l2 };
    unsigned fi = 0;
    uint32_t fo = 0;
    uint32_t left = l1 + l2;
    uint32_t chunk = seg_cap(tcp) - (5u + 1u + 16u);
    if (chunk > TLS13_PLAIN_MAX) chunk = TLS13_PLAIN_MAX;
    while (left) {
        /* 平文をレコードの中へ直接組み立て、その場で暗号化する */
        const uint32_t take = left < chunk ? left : chunk;
        uint8_t *dst = s->rec + 5;
        for (uint32_t got = 0; got < take;) {
            while (fo == fl[fi]) { fi++; fo = 0; }
            uint32_t c = fl[fi] - fo;
            if (c > take - got) c = take - got;
            memcpy(dst + got, f[fi] + fo, c);
            fo += c;
            got += c;
        }
        const size_t rl = tls13_seal(&s->t, dst, take, s->rec);
        if (g_nvmet_tls_corrupt) {   /* 検証用: 暗号文を 1 ビット壊す(相手が bad_record_mac で切るか)*/
            g_nvmet_tls_corrupt--;
            s->rec[rl - 1] ^= 0x01;
            uart_printf("[nvmet-tls] 検証用にレコード 1 個の暗号文を壊して送る\n");
        }
        if (tcp_send_async2(tcp, s->rec, (uint16_t)rl, NULL, 0) < 0) {
            s->failed = 1;
            return -1;
        }
        s->tx_records++;
        s->tx_bytes += take;
        left -= take;
    }
    return 0;
}

/* ---- 段階 F: イニシエータ側 ---- */
static char  s_cli_key[256];
static char  s_cli_keylog_path[256];
static FILE *s_cli_keylog;

static void cli_keylog_write(void *arg, const char *line) {
    (void)arg;
    if (!s_cli_keylog && s_cli_keylog_path[0]) s_cli_keylog = fopen(s_cli_keylog_path, "a");
    if (!s_cli_keylog) return;
    fprintf(s_cli_keylog, "%s\n", line);
    fflush(s_cli_keylog);
}

int nvme_tls_client_enabled(void) { return s_cli_key[0] != 0; }

void nvme_tls_client_shell(const char *args) {
    char buf[512];
    strncpy(buf, args, sizeof(buf) - 1u);
    buf[sizeof(buf) - 1u] = 0;
    char *tok[3];
    unsigned nt = 0;
    char *save = 0;
    for (char *p = strtok_r(buf, " \t\r\n", &save); p && nt < 3u; p = strtok_r(0, " \t\r\n", &save)) tok[nt++] = p;
    if (nt == 1 && !strcmp(tok[0], "off")) {
        crypto_wipe(s_cli_key, sizeof(s_cli_key));
    } else if (nt >= 1) {
        /* 形式だけ先に確かめる(身元は接続先の subnqn で決まるので、ここでは仮の NQN)*/
        tls13_psk_t p[2];
        const char *why = "";
        if (tls13_nvme_psk(p, tok[0], "nqn.check", "nqn.check", &why) < 0) {
            uart_printf("nvmetls: 鍵が使えない(%s)\n使い方: nvmetls <NVMeTLSkey-1:01:..:> [keylog <path>] / nvmetls off\n", why);
            return;
        }
        crypto_wipe(p, sizeof(p));
        strncpy(s_cli_key, tok[0], sizeof(s_cli_key) - 1u);
        s_cli_keylog_path[0] = 0;
        if (s_cli_keylog) {
            fclose(s_cli_keylog);
            s_cli_keylog = NULL;
        }
        if (nt >= 3 && !strcmp(tok[1], "keylog")) strncpy(s_cli_keylog_path, tok[2], sizeof(s_cli_keylog_path) - 1u);
    }
    uart_printf(s_cli_key[0] ? "nvmetls: 内蔵イニシエータは `tcpbench ... tls` で TLS 1.3 を使う(鍵の書き出し: %s)\n"
                             : "nvmetls: イニシエータの TLS の鍵なし%s\n",
                s_cli_key[0] ? (s_cli_keylog_path[0] ? s_cli_keylog_path : "しない") : "");
}

int nvme_tls_client_start(nvmet_tls_conn_t *s, tcp_conn_t *tcp, const char *hostnqn, const char *subnqn) {
    tls13_psk_t p[2];
    const char *why = "";
    if (!s_cli_key[0] || tls13_nvme_psk(p, s_cli_key, hostnqn, subnqn, &why) < 0) {
        uart_printf("[!] nvme-tls: 鍵が無い / 使えない(%s)\n", why);
        return -1;
    }
    s->cpsk = p[0];   /* 身元の版 1(nvme gen-tls-key --identity=1 と同じ)*/
    crypto_wipe(p, sizeof(p));
    tls13_client_init(&s->t, &s->cpsk);
    s->t.keylog = cli_keylog_write;
    s->pendlen = 0;
    s->applen = s->apphead = 0;
    s->failed = 0;
    s->rx_records = s->tx_records = s->rx_bytes = s->tx_bytes = 0;
    const size_t n = tls13_client_hello(&s->t, s->pend, sizeof(s->pend));
    if (!n) return -1;
    s->pendlen = n;
    uart_printf("[nvme-tls] ClientHello を送る(身元 %.60s...)\n", s->cpsk.identity);
    return flush_pend(s, tcp, 1);
}

void nvmet_tls_close(nvmet_tls_conn_t *s, tcp_conn_t *tcp) {
    if (tcp->state == TCP_ESTABLISHED || tcp->state == TCP_CLOSE_WAIT) {
        flush_pend(s, tcp, 0);
        if (!s->failed && s->t.state == TLS13_ST_OPEN) {
            const size_t n = tls13_close(&s->t, s->rec);
            if (n) send_raw(tcp, s->rec, n);
        }
    }
    crypto_wipe(&s->t, sizeof(s->t));
    s->applen = s->apphead = s->pendlen = 0;
}
