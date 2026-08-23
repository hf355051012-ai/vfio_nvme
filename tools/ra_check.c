/*
 * ra_check -- `slaactest dump` が出す Router Advertisement のバイト列を、
 * **このリポジトリのコードを一切 include せず** Linux/libc の構造体だけで
 * 読み直す。
 *
 *   <netinet/icmp6.h> の struct nd_router_advert
 *       ND_ROUTER_ADVERT(134)、cur hop limit / フラグ / ルータ寿命は
 *       icmp6_hdr の type 固有 4 バイト(byte 4-7)に載る
 *   <netinet/icmp6.h> の struct nd_opt_prefix_info
 *       32 バイト固定。プレフィックス本体はオプション先頭から 16
 *
 * **RA は「本体 16 バイトのどこに何があるか」を間違えやすい。** ルータ寿命を
 * byte 4-5 に書く(cur hop limit と衝突)、reachable time の位置を 4 バイト
 * ずらす、Prefix Information の valid/preferred を入れ替える、といった
 * 取り違えは、自作の注入側と自作の受信側だけで試すと**両方が同じ間違い方を
 * して絶対に検出できない**(CRC32C と NDP の Target Address で実際に踏んだ穴)。
 * ここで libc の構造体に読ませることで、その穴を塞ぐ。
 * tools/disc_log_check.c / ip_frag_check.c / icmp_mtu_check.c と同じ考え方。
 *
 * ビルド:
 *   gcc -O2 -Wall -Wextra -o /tmp/ra_check tools/ra_check.c
 * 使い方:
 *   slaactest dump の出力を丸ごと標準入力へ流す
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <netinet/icmp6.h>   /* struct nd_router_advert, nd_opt_prefix_info, ND_* */
#include <arpa/inet.h>

#define MAX_MSG 512

/*
 * "aa bb cc ..." を読み取る。戻り値はバイト数。
 */
static int parse_hex(const char *p, unsigned char *out, int max)
{
    int n = 0;
    while (*p && n < max) {
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
        if (!*p) break;
        unsigned v;
        if (sscanf(p, "%2x", &v) != 1) break;
        out[n++] = (unsigned char)v;
        while (*p && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r') p++;
    }
    return n;
}

/*
 * libc の構造体が、こちらが前提にしているバイト配置と本当に一致するかを
 * 先に表示する。**自作側の定数(RA_OFF_* / PIO_OFF_*)はこの値を写したもの**
 * なので、ここがずれていればそれ自体が発見になる。
 */
static void print_offsets(void)
{
    printf("=== libc の構造体オフセット(自作側の RA_OFF_* / PIO_OFF_* はこれと一致すべき)===\n");
    printf("  nd_router_advert: 全体 %zu バイト(= 本体 16)\n", sizeof(struct nd_router_advert));
    printf("    cur hop limit    = %zu (RA_OFF_CUR_HOP_LIMIT=4)\n",
           offsetof(struct nd_router_advert, nd_ra_hdr) +
           offsetof(struct icmp6_hdr, icmp6_dataun) + 0);
    printf("    flags            = %zu (RA_OFF_FLAGS=5)\n",
           offsetof(struct nd_router_advert, nd_ra_hdr) +
           offsetof(struct icmp6_hdr, icmp6_dataun) + 1);
    printf("    router lifetime  = %zu (RA_OFF_ROUTER_LIFETIME=6)\n",
           offsetof(struct nd_router_advert, nd_ra_hdr) +
           offsetof(struct icmp6_hdr, icmp6_dataun) + 2);
    printf("    reachable time   = %zu (RA_OFF_REACHABLE=8)\n",
           offsetof(struct nd_router_advert, nd_ra_reachable));
    printf("    retrans timer    = %zu (RA_OFF_RETRANS=12)\n",
           offsetof(struct nd_router_advert, nd_ra_retransmit));
    printf("  nd_opt_prefix_info: 全体 %zu バイト(PIO_LEN=32)\n",
           sizeof(struct nd_opt_prefix_info));
    printf("    prefix_len       = %zu (PIO_OFF_PREFIX_LEN=2)\n",
           offsetof(struct nd_opt_prefix_info, nd_opt_pi_prefix_len));
    printf("    flags            = %zu (PIO_OFF_FLAGS=3)\n",
           offsetof(struct nd_opt_prefix_info, nd_opt_pi_flags_reserved));
    printf("    valid time       = %zu (PIO_OFF_VALID=4)\n",
           offsetof(struct nd_opt_prefix_info, nd_opt_pi_valid_time));
    printf("    preferred time   = %zu (PIO_OFF_PREFERRED=8)\n",
           offsetof(struct nd_opt_prefix_info, nd_opt_pi_preferred_time));
    printf("    prefix           = %zu (PIO_OFF_PREFIX=16)\n",
           offsetof(struct nd_opt_prefix_info, nd_opt_pi_prefix));
    printf("\n");
}

static int check_ra(const unsigned char *buf, int len)
{
    int ok = 1;
    if (len < (int)sizeof(struct nd_router_advert)) {
        printf("  NG: 短すぎる (len=%d、RA 本体 %zu が必要)\n",
               len, sizeof(struct nd_router_advert));
        return 0;
    }

    struct nd_router_advert ra;
    memcpy(&ra, buf, sizeof(ra));

    printf("  type=%u code=%u", ra.nd_ra_type, ra.nd_ra_code);
    if (ra.nd_ra_type != ND_ROUTER_ADVERT) {
        printf("  <- NG(ND_ROUTER_ADVERT=%u であるべき)", ND_ROUTER_ADVERT);
        ok = 0;
    }
    if (ra.nd_ra_code != 0) {
        printf("  <- NG(code は 0)");
        ok = 0;
    }
    printf("\n");

    unsigned rlife = ntohs(ra.nd_ra_router_lifetime);
    printf("  cur_hop_limit=%u flags=0x%02x(M=%d O=%d) router_lifetime=%us\n",
           ra.nd_ra_curhoplimit, ra.nd_ra_flags_reserved,
           (ra.nd_ra_flags_reserved & ND_RA_FLAG_MANAGED) ? 1 : 0,
           (ra.nd_ra_flags_reserved & ND_RA_FLAG_OTHER) ? 1 : 0, rlife);
    printf("  reachable_time=%ums retrans_timer=%ums\n",
           ntohl(ra.nd_ra_reachable), ntohl(ra.nd_ra_retransmit));

    /* ルータ寿命を cur hop limit と同じ 4-5 バイトへ書いてしまう取り違えは、
     * 「cur_hop_limit が 0 でルータ寿命が妙に大きい」形で現れる。 */
    if (ra.nd_ra_curhoplimit == 0 && rlife > 0xFF00u) {
        printf("  NG: cur_hop_limit=0 かつ router_lifetime が異様に大きい"
               "(byte 4-5 へルータ寿命を書いていないか)\n");
        ok = 0;
    }

    /* ---- オプション走査 ---- */
    int off = (int)sizeof(struct nd_router_advert);
    int saw_prefix = 0;
    while (off + 2 <= len) {
        struct nd_opt_hdr oh;
        memcpy(&oh, buf + off, sizeof(oh));
        int olen = oh.nd_opt_len * 8;
        if (olen == 0) {
            printf("  NG: 長さ 0 のオプション (type=%u) -- RFC 4861 4.6 で不正\n",
                   oh.nd_opt_type);
            return 0;
        }
        if (off + olen > len) {
            printf("  NG: オプションがメッセージ末尾を越える (type=%u off=%d len=%d)\n",
                   oh.nd_opt_type, off, olen);
            return 0;
        }

        if (oh.nd_opt_type == ND_OPT_SOURCE_LINKADDR) {
            const unsigned char *m = buf + off + 2;
            printf("  option[%d] Source Link-Layer Address: %02x:%02x:%02x:%02x:%02x:%02x\n",
                   off, m[0], m[1], m[2], m[3], m[4], m[5]);
            if (olen != 8) {
                printf("  NG: Ethernet の SLLA は 8 バイト(len=1)であるべき\n");
                ok = 0;
            }
        } else if (oh.nd_opt_type == ND_OPT_PREFIX_INFORMATION) {
            saw_prefix = 1;
            if (olen != (int)sizeof(struct nd_opt_prefix_info)) {
                printf("  NG: Prefix Information は %zu バイト(len=4)であるべきなのに %d\n",
                       sizeof(struct nd_opt_prefix_info), olen);
                ok = 0;
            } else {
                struct nd_opt_prefix_info pi;
                memcpy(&pi, buf + off, sizeof(pi));
                char pfx[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &pi.nd_opt_pi_prefix, pfx, sizeof(pfx));
                unsigned valid = ntohl(pi.nd_opt_pi_valid_time);
                unsigned pref  = ntohl(pi.nd_opt_pi_preferred_time);
                printf("  option[%d] Prefix Information: %s/%u  L=%d A=%d "
                       "valid=%us preferred=%us\n",
                       off, pfx, pi.nd_opt_pi_prefix_len,
                       (pi.nd_opt_pi_flags_reserved & ND_OPT_PI_FLAG_ONLINK) ? 1 : 0,
                       (pi.nd_opt_pi_flags_reserved & ND_OPT_PI_FLAG_AUTO) ? 1 : 0,
                       valid, pref);
                /* valid と preferred を入れ替える取り違えはここで捕まる
                 * (RFC 4862 5.5.3 は preferred <= valid を要求する)。 */
                if (pref > valid) {
                    printf("  NG: preferred(%u) > valid(%u)"
                           "(4-7 と 8-11 を入れ替えていないか)\n", pref, valid);
                    ok = 0;
                }
                if (pi.nd_opt_pi_prefix_len == 0 || pi.nd_opt_pi_prefix_len > 128) {
                    printf("  NG: prefix_len=%u が範囲外(byte 2 に書いているか)\n",
                           pi.nd_opt_pi_prefix_len);
                    ok = 0;
                }
                /* プレフィックス長より下のビットは 0 でなければならない
                 * (RFC 4861 4.6.2)。オフセットを取り違えて EUI-64 まで
                 * 書き込んでいるとここで出る。 */
                for (int b = pi.nd_opt_pi_prefix_len; b < 128; b++) {
                    const unsigned char *pb = (const unsigned char *)&pi.nd_opt_pi_prefix;
                    if (pb[b / 8] & (0x80u >> (b % 8))) {
                        printf("  NG: prefix_len=%u より下位のビットが 0 でない\n",
                               pi.nd_opt_pi_prefix_len);
                        ok = 0;
                        break;
                    }
                }
            }
        } else if (oh.nd_opt_type == ND_OPT_MTU) {
            if (olen != (int)sizeof(struct nd_opt_mtu)) {
                printf("  NG: MTU オプションは %zu バイト(len=1)であるべきなのに %d\n",
                       sizeof(struct nd_opt_mtu), olen);
                ok = 0;
            } else {
                struct nd_opt_mtu mo;
                memcpy(&mo, buf + off, sizeof(mo));
                printf("  option[%d] MTU: %u\n", off, ntohl(mo.nd_opt_mtu_mtu));
                if (ntohl(mo.nd_opt_mtu_mtu) == 0) {
                    printf("  NG: MTU が 0(reserved の 2-3 バイトへ書いていないか)\n");
                    ok = 0;
                }
            }
        } else {
            printf("  option[%d] type=%u len=%d(このツールでは検査しない)\n",
                   off, oh.nd_opt_type, olen);
        }
        off += olen;
    }
    if (off != len) {
        printf("  NG: オプションの合計長がメッセージ長と一致しない (off=%d len=%d)\n",
               off, len);
        ok = 0;
    }
    if (!saw_prefix) {
        printf("  注記: Prefix Information が無い RA(ルータ寿命 0 の取り消しなどでは正常)\n");
    }
    return ok;
}

int main(void)
{
    char line[8192];
    int groups = 0, failures = 0;

    print_offsets();

    while (fgets(line, sizeof(line), stdin)) {
        char *p = strstr(line, "RADUMP ");
        if (!p) continue;
        p += strlen("RADUMP ");

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

        groups++;
        printf("=== RA %d (%d バイト) ===\n", groups, n);
        int ok = check_ra(buf, n);
        printf("  -> %s\n", ok ? "OK" : "NG");
        if (!ok) failures++;
    }

    if (groups == 0) {
        printf("RADUMP 行が 1 つも見つかりませんでした"
               "(`slaactest dump` の出力を流してください)\n");
        return 2;
    }
    printf("\n%d 個中 %d 個が NG -> %s\n", groups, failures,
           failures ? "FAIL" : "PASS");
    return failures ? 1 : 0;
}
