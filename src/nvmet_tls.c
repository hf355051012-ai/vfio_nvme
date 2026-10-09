/* NVMe/TCP ターゲットの TLS 1.3(PLAN_auth_tls.md 段階 D)。仕様は nvmet_tls.h。 */
#include "nvmet_tls.h"
#include "nvmet.h"
#include "uart.h"

#include <stdio.h>
#include <string.h>

/* PSK は身元の版 1 / 版 0 の 2 本(tls13_nvme_psk())。 */
static tls13_psk_t s_psk[2];
static unsigned    s_npsk;
static char        s_hostnqn[256];
static char        s_keylog_path[256];
static FILE       *s_keylog;

int nvmet_tls_enabled(void) { return s_npsk != 0; }

/* SSLKEYLOGFILE 形式で追記する。Precision の tshark に `-o tls.keylog_file:<path>` で
 * 渡すと、こちらが出した暗号文を相手側の道具で復号して読める(段階 D の確かめ方)。 */
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

    if (nt == 1 && !strcmp(tok[0], "off")) {
        crypto_wipe(s_psk, sizeof(s_psk));
        s_npsk = 0;
    } else if (nt >= 2) {
        const char *why = "";
        tls13_psk_t p[2];
        if (tls13_nvme_psk(p, tok[1], tok[0], NVMET_SUBNQN, &why) < 0) {
            uart_printf("nvmettls: 鍵が使えない(%s)\n"
                        "使い方: nvmettls <hostnqn> <NVMeTLSkey-1:01:..:> [keylog <path>] / nvmettls off\n", why);
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
    s->applen = 0;
}

static int send_all(tcp_conn_t *tcp, const uint8_t *p, size_t n) {
    return (n == 0 || tcp_send(tcp, p, (uint32_t)n) == (int)n) ? 0 : -1;
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
    size_t ol = 0;
    const int rc = tls13_input(&s->t, s->in, (size_t)n, s->out, sizeof(s->out), &ol,
                               s->app, sizeof(s->app), &s->applen);
    if (send_all(tcp, s->out, ol) != 0) return -1;
    if (rc != 0) {
        if (s->t.alert_sent != 0xFF)
            uart_printf("[!] nvmet-tls: 握手に失敗(%s、alert %s を送った)\n", s->t.why ? s->t.why : "?",
                        tls13_alert_name(s->t.alert_sent));
        else
            uart_printf("[!] nvmet-tls: 相手が alert %s を送ってきた\n", tls13_alert_name(s->t.alert_recv));
        return -1;
    }
    if (before == TLS13_ST_WAIT_CH && s->t.state == TLS13_ST_WAIT_CFIN) {
        uart_printf("[nvmet-tls] ClientHello を受理(身元 %.60s...)\n", s->t.psks[s->t.psk_index].identity);
    }
    if (before != TLS13_ST_OPEN && s->t.state == TLS13_ST_OPEN) {
        uart_printf("[nvmet-tls] 握手が済んだ(TLS 1.3、TLS_AES_128_GCM_SHA256、x25519、身元の版 %d)\n",
                    s->t.psk_index == 0 ? 1 : 0);
    }
    return s->t.state == TLS13_ST_OPEN ? 1 : 0;
}

void nvmet_tls_close(nvmet_tls_conn_t *s, tcp_conn_t *tcp) {
    uint8_t rec[64];
    const size_t n = tls13_close(&s->t, rec);
    if (n) send_all(tcp, rec, n);
    crypto_wipe(&s->t, sizeof(s->t));
}
