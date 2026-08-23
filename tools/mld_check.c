/*
 * mld_check -- `mldtest dump` が出す MLD のバイト列を、**このリポジトリの
 * コードを一切 include せず** Linux/libc の定義だけで読み直す。
 *
 *   MLDv1 (RFC 2710): <netinet/icmp6.h> の struct mld_hdr
 *       type/code/cksum + Maximum Response Delay(4-5)+ reserved(6-7)
 *       + multicast address(8-23)= 24 バイト固定
 *   MLDv2 (RFC 3810): 報告本体は <netinet/icmp6.h> の struct icmp6_hdr で読む。
 *       Linux の include/net/mld.h は
 *         #define mld2r_resv2  icmp6_dataun.un_data16[0]   (byte 4-5)
 *         #define mld2r_ngrec  icmp6_dataun.un_data16[1]   (byte 6-7)
 *       と定義しているので、**レコード数は 6-7**。ここを 4-5 と取り違える
 *       のがいちばんありがちな間違いで、libc の icmp6_data16[1] に読ませれば
 *       そのまま検算になる。
 *
 * **Multicast Address Record(struct mld2_grec)だけは転記**。Linux の
 * include/net/mld.h はカーネル専用の型(__u8 / __be16 / struct in6_addr の
 * カーネル版)を引くのでユーザ空間から include できない。転記が正しいことは
 *   (1) _Static_assert でサイズとオフセットを固定する
 *   (2) **Linux 自身が送った MLDv2 Report を同じツールに食わせて読めること**
 *       (tools/sniff_mld.py が MLDDUMP 形式で吐く)
 * の 2 つで担保する。
 *
 * tools/disc_log_check.c / ip_frag_check.c / icmp_mtu_check.c / ra_check.c と
 * 同じ考え方。
 *
 * ビルド:
 *   gcc -O2 -Wall -Wextra -o /tmp/mld_check tools/mld_check.c
 * 使い方:
 *   mldtest dump の出力、または tools/sniff_mld.py の出力を標準入力へ流す
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <netinet/icmp6.h>   /* struct mld_hdr, struct icmp6_hdr, MLD_LISTENER_* */
#include <netinet/in.h>
#include <arpa/inet.h>

#define MAX_MSG 1024

/* Linux の include/net/mld.h より転記(上のコメントを参照)。 */
struct grec {
    uint8_t         grec_type;
    uint8_t         grec_auxwords;
    uint16_t        grec_nsrcs;      /* ネットワークバイトオーダー */
    struct in6_addr grec_mca;
};
_Static_assert(sizeof(struct grec) == 20, "MLDv2 のレコードは 20 バイト");
_Static_assert(offsetof(struct grec, grec_nsrcs) == 2, "nsrcs は byte 2-3");
_Static_assert(offsetof(struct grec, grec_mca) == 4, "グループアドレスは byte 4 から");
/* MLDv1 は 24 バイト固定(icmp6 ヘッダ 8 + アドレス 16)。 */
_Static_assert(sizeof(struct mld_hdr) == 24, "MLDv1 は 24 バイト");

static int parse_hex(const char *p, unsigned char *out, int max)
{
    int n = 0;
    while (*p && n < max) {
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
        if (!*p) break;
        unsigned v;
        if (sscanf(p, "%2x", &v) != 1) break;
        out[n++] = (unsigned char)v;
        while (*p && *p != ' ' && *p != '\t' && *p != '\r' && *p != '\n') p++;
    }
    return n;
}

static const char *rec_type_name(unsigned t)
{
    switch (t) {
    case 1: return "MODE_IS_INCLUDE";
    case 2: return "MODE_IS_EXCLUDE";
    case 3: return "CHANGE_TO_INCLUDE(離脱)";
    case 4: return "CHANGE_TO_EXCLUDE(参加)";
    case 5: return "ALLOW_NEW_SOURCES";
    case 6: return "BLOCK_OLD_SOURCES";
    default: return "不明";
    }
}

static int check_v1(const unsigned char *buf, int len)
{
    int ok = 1;
    if (len != (int)sizeof(struct mld_hdr)) {
        printf("  NG: MLDv1 は %zu バイト固定なのに %d バイト\n",
               sizeof(struct mld_hdr), len);
        return 0;
    }
    struct mld_hdr m;
    memcpy(&m, buf, sizeof(m));

    const char *name = (m.mld_type == MLD_LISTENER_REPORT)    ? "Report"
                     : (m.mld_type == MLD_LISTENER_REDUCTION) ? "Done"
                     : (m.mld_type == MLD_LISTENER_QUERY)     ? "Query" : "不明";
    char addr[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &m.mld_addr, addr, sizeof(addr));
    printf("  MLDv1 %s (type=%u code=%u) maxdelay=%ums group=%s\n",
           name, m.mld_type, m.mld_code, ntohs(m.mld_maxdelay), addr);

    if (m.mld_code != 0) {
        printf("  NG: code は 0 でなければならない\n");
        ok = 0;
    }
    if (m.mld_type != MLD_LISTENER_QUERY && ntohs(m.mld_maxdelay) != 0) {
        printf("  NG: Report/Done の Maximum Response Delay は 0"
               "(4-5 と 6-7 を取り違えていないか)\n");
        ok = 0;
    }
    /* Report/Done のグループはマルチキャストでなければ意味を成さない。 */
    if (m.mld_type != MLD_LISTENER_QUERY &&
        ((const unsigned char *)&m.mld_addr)[0] != 0xFF) {
        printf("  NG: グループがマルチキャストアドレスでない"
               "(オフセット 8 から 16 バイトに置いているか)\n");
        ok = 0;
    }
    return ok;
}

static int check_v2_report(const unsigned char *buf, int len)
{
    int ok = 1;
    if (len < (int)sizeof(struct icmp6_hdr)) {
        printf("  NG: 短すぎる (len=%d)\n", len);
        return 0;
    }
    struct icmp6_hdr h;
    memcpy(&h, buf, sizeof(h));

    /* **ここが本題**: レコード数は icmp6_data16[1](= byte 6-7)。 */
    unsigned ngrec = ntohs(h.icmp6_data16[1]);
    unsigned resv2 = ntohs(h.icmp6_data16[0]);
    printf("  MLDv2 Report (type=%u code=%u) reserved=%u レコード数=%u\n",
           h.icmp6_type, h.icmp6_code, resv2, ngrec);

    if (h.icmp6_type != 143) {
        printf("  NG: MLDv2 Report の type は 143\n");
        ok = 0;
    }
    if (resv2 != 0) {
        printf("  NG: byte 4-5 は reserved で 0 のはず"
               "(レコード数をここに書いていないか)\n");
        ok = 0;
    }
    if (ngrec == 0) {
        printf("  NG: レコード数が 0(byte 6-7 に入れているか)\n");
        ok = 0;
    }

    int off = (int)sizeof(struct icmp6_hdr);
    for (unsigned i = 0; i < ngrec; i++) {
        if (off + (int)sizeof(struct grec) > len) {
            printf("  NG: レコード %u がメッセージ末尾を越える (off=%d len=%d)\n",
                   i + 1, off, len);
            return 0;
        }
        struct grec g;
        memcpy(&g, buf + off, sizeof(g));
        unsigned nsrcs = ntohs(g.grec_nsrcs);
        char addr[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &g.grec_mca, addr, sizeof(addr));
        printf("  レコード %u: 種別=%u(%s) 補助語=%u 送信元数=%u group=%s\n",
               i + 1, g.grec_type, rec_type_name(g.grec_type),
               g.grec_auxwords, nsrcs, addr);

        if (g.grec_type < 1 || g.grec_type > 6) {
            printf("  NG: レコード種別が範囲外\n");
            ok = 0;
        }
        if (((const unsigned char *)&g.grec_mca)[0] != 0xFF) {
            printf("  NG: グループがマルチキャストアドレスでない"
                   "(レコード内オフセット 4 に置いているか)\n");
            ok = 0;
        }
        /* 送信元指定を使わないなら 0。ここが 0 でないのに送信元が無いと、
         * 読み手はレコード長を取り違えて次のレコードを見失う。 */
        off += (int)sizeof(struct grec) + (int)(nsrcs * 16u) + g.grec_auxwords * 4;
    }
    if (off != len) {
        printf("  NG: レコードの合計長がメッセージ長と一致しない (off=%d len=%d)\n",
               off, len);
        ok = 0;
    }
    return ok;
}

int main(void)
{
    char line[8192];
    int groups = 0, failures = 0;

    printf("=== libc / Linux の定義(自作側の定数はこれと一致すべき)===\n");
    printf("  MLDv1 struct mld_hdr        = %zu バイト、group は offset %zu\n",
           sizeof(struct mld_hdr), offsetof(struct mld_hdr, mld_addr));
    printf("  MLDv2 レコード数の位置      = icmp6_data16[1] = byte 6-7\n");
    printf("  MLDv2 struct grec           = %zu バイト、group は offset %zu\n\n",
           sizeof(struct grec), offsetof(struct grec, grec_mca));

    while (fgets(line, sizeof(line), stdin)) {
        char *p = strstr(line, "MLDDUMP ");
        if (!p) continue;
        p += strlen("MLDDUMP ");

        int len;
        if (sscanf(p, "len=%d", &len) != 1) continue;
        char *hex = strstr(p, "len=");
        if (!hex) continue;
        while (*hex && *hex != ' ') hex++;

        unsigned char buf[MAX_MSG];
        int n = parse_hex(hex, buf, MAX_MSG);
        if (n != len) {
            printf("警告: len=%d と読み取れた %d バイトが一致しません\n", len, n);
        }
        if (n < 4) continue;

        groups++;
        printf("=== MLD %d (%d バイト) ===\n", groups, n);
        int ok;
        if (buf[0] == 143) {
            ok = check_v2_report(buf, n);
        } else if (buf[0] == MLD_LISTENER_QUERY && n >= 28) {
            printf("  MLDv2 Query (%d バイト >= 28 なので v2)\n", n);
            ok = check_v1(buf, 24);   /* 先頭 24 バイトの配置は v1 と共通 */
        } else {
            ok = check_v1(buf, n);
        }
        printf("  -> %s\n", ok ? "OK" : "NG");
        if (!ok) failures++;
    }

    if (groups == 0) {
        printf("MLDDUMP 行が 1 つも見つかりませんでした"
               "(`mldtest dump` の出力を流してください)\n");
        return 2;
    }
    printf("\n%d 個中 %d 個が NG -> %s\n", groups, failures, failures ? "FAIL" : "PASS");
    return failures ? 1 : 0;
}
