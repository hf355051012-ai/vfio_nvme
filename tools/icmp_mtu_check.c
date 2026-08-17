/*
 * icmp_mtu_check -- `pmtutest dump` が出す ICMP バイト列を、**このリポジトリの
 * コードを一切 include せず** Linux/libc の構造体だけで読み直す。
 *
 *   IPv4: <netinet/ip_icmp.h> の struct icmphdr(ICMP_DEST_UNREACH /
 *         ICMP_FRAG_NEEDED、MTU は un.frag.mtu = 未使用 4 バイトの下位 16bit)
 *   IPv6: <netinet/icmp6.h> の struct icmp6_hdr(ICMP6_PACKET_TOO_BIG、
 *         MTU は icmp6_mtu = 4-7 バイトの 32bit 全体)
 *
 * **この 2 つは MTU の置き場所が違う。** IPv4 と同じつもりで IPv6 の下位 16bit
 * だけに書く(あるいは逆)という取り違えは、自作の送信側と自作の受信側だけで
 * 試すと両方が同じ間違い方をして絶対に検出できない(CRC32C で実際に踏んだ穴)。
 * ここで libc の構造体に読ませることで、その穴を塞ぐ。
 * tools/disc_log_check.c / tools/ip_frag_check.c と同じ考え方。
 *
 * ビルド:
 *   gcc -O2 -Wall -Wextra -o /tmp/icmp_mtu_check tools/icmp_mtu_check.c
 * 使い方:
 *   pmtutest dump の出力を丸ごと標準入力へ流す
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>        /* struct ip */
#include <netinet/ip_icmp.h>   /* struct icmphdr, ICMP_DEST_UNREACH, ICMP_FRAG_NEEDED */
#include <netinet/ip6.h>       /* struct ip6_hdr */
#include <netinet/icmp6.h>     /* struct icmp6_hdr, ICMP6_PACKET_TOO_BIG */
#include <arpa/inet.h>

#define MAX_MSG 256

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

static int check_v4(const unsigned char *buf, int len)
{
    int ok = 1;
    if (len < (int)(sizeof(struct icmphdr) + sizeof(struct ip))) {
        printf("  NG: 短すぎる (len=%d、ICMP 8 + 引用 IP ヘッダ 20 が必要)\n", len);
        return 0;
    }

    struct icmphdr ih;
    memcpy(&ih, buf, sizeof(ih));

    printf("  type=%u code=%u", ih.type, ih.code);
    if (ih.type != ICMP_DEST_UNREACH) {
        printf("  <- NG(ICMP_DEST_UNREACH=%u であるべき)", ICMP_DEST_UNREACH);
        ok = 0;
    }
    if (ih.code != ICMP_FRAG_NEEDED) {
        printf("  <- NG(ICMP_FRAG_NEEDED=%u であるべき)", ICMP_FRAG_NEEDED);
        ok = 0;
    }
    printf("\n");

    /* ここが本題。glibc の struct icmphdr は
     *   un.frag = { uint16_t __glibc_reserved; uint16_t mtu; }
     * と定義されている。つまりワイヤ上の byte 4-5 は予約(0)、**byte 6-7 が
     * MTU**。自作側がこの並びを取り違えていれば値が合わない。
     * (予約フィールドの名前は libc によって __unused 等に変わるが、
     *  レイアウトは同じ。ここは glibc 前提。) */
    unsigned mtu = ntohs(ih.un.frag.mtu);
    unsigned unused = ntohs(ih.un.frag.__glibc_reserved);
    printf("  un.frag.__glibc_reserved=%u un.frag.mtu=%u\n", unused, mtu);
    if (unused != 0) {
        printf("  NG: RFC 1191 では未使用の上位 16bit は 0 でなければならない\n");
        ok = 0;
    }
    if (mtu == 0) {
        printf("  NG: MTU が 0(byte 4-5 に書いてしまっていないか)\n");
        ok = 0;
    }
    /* このツールの役目は**フィールド配置の検算**。値が仕様の下限を満たすかは
     * 受信側の責任(pmtutest [7] が確かめている)なので、ここでは注記だけ。
     * 床テスト用に意図的に小さい値を注入することがある。 */
    if (mtu != 0 && mtu < 576) {
        printf("  注記: MTU=%u は RFC 1191 の実用下限 576 を下回る"
               "(受信側が採用しないことを別途確認する)\n", mtu);
    }

    /* 引用された元 IPv4 ヘッダ。DF が立っていないと Frag Needed の前提が崩れる。 */
    struct ip q;
    memcpy(&q, buf + sizeof(struct icmphdr), sizeof(q));
    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &q.ip_src, src, sizeof(src));
    inet_ntop(AF_INET, &q.ip_dst, dst, sizeof(dst));
    unsigned off = ntohs(q.ip_off);
    printf("  引用: %s -> %s  DF=%d proto=%u\n", src, dst, (off & IP_DF) ? 1 : 0, q.ip_p);
    if (q.ip_v != 4) {
        printf("  NG: 引用ヘッダの version が %u\n", q.ip_v);
        ok = 0;
    }
    if (!(off & IP_DF)) {
        printf("  NG: 引用ヘッダに DF が立っていない(Frag Needed の前提)\n");
        ok = 0;
    }
    return ok;
}

static int check_v6(const unsigned char *buf, int len)
{
    int ok = 1;
    if (len < (int)(sizeof(struct icmp6_hdr) + sizeof(struct ip6_hdr))) {
        printf("  NG: 短すぎる (len=%d、ICMPv6 8 + 引用 IPv6 ヘッダ 40 が必要)\n", len);
        return 0;
    }

    struct icmp6_hdr ih;
    memcpy(&ih, buf, sizeof(ih));

    printf("  type=%u code=%u", ih.icmp6_type, ih.icmp6_code);
    if (ih.icmp6_type != ICMP6_PACKET_TOO_BIG) {
        printf("  <- NG(ICMP6_PACKET_TOO_BIG=%u であるべき)", ICMP6_PACKET_TOO_BIG);
        ok = 0;
    }
    if (ih.icmp6_code != 0) {
        printf("  <- NG(code は 0)");
        ok = 0;
    }
    printf("\n");

    /* ここが本題。icmp6_mtu は 4-7 バイトの 32bit 全体。IPv4 と違い上位 16bit も
     * MTU の一部なので、IPv4 と同じつもりで下位 16bit だけに書くと桁が狂う。 */
    unsigned mtu = ntohl(ih.icmp6_mtu);
    printf("  icmp6_mtu=%u(32bit 全体)\n", mtu);
    if (mtu == 0) {
        printf("  NG: MTU が 0\n");
        ok = 0;
    }
    /* 上位 16bit へ書いてしまうと 32bit として読んだときに巨大な値になる
     * (= IPv4 のつもりで下位だけに書く / 逆に上位へ書く、の取り違えを捕まえる)。 */
    if (mtu > 0xFFFFu) {
        printf("  NG: MTU が 65535 を超えている(上位 16bit へ書いていないか)\n");
        ok = 0;
    }
    /* このツールの役目は**フィールド配置の検算**。値が仕様の下限を満たすかは
     * 受信側の責任(pmtutest [7] が確かめている)なので、ここでは注記だけ。
     * 床テスト用に意図的に小さい値を注入することがある。 */
    if (mtu != 0 && mtu < 1280) {
        printf("  注記: MTU=%u は RFC 8201 の IPv6 最小 MTU 1280 を下回る"
               "(受信側が採用しないことを別途確認する)\n", mtu);
    }

    struct ip6_hdr q;
    memcpy(&q, buf + sizeof(struct icmp6_hdr), sizeof(q));
    char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &q.ip6_src, src, sizeof(src));
    inet_ntop(AF_INET6, &q.ip6_dst, dst, sizeof(dst));
    printf("  引用: %s -> %s  next_header=%u\n", src, dst, q.ip6_nxt);
    if (((ntohl(q.ip6_flow) >> 28) & 0xF) != 6) {
        printf("  NG: 引用ヘッダの version が 6 でない\n");
        ok = 0;
    }
    return ok;
}

int main(void)
{
    char line[4096];
    int groups = 0, failures = 0;

    while (fgets(line, sizeof(line), stdin)) {
        char *p = strstr(line, "ICMPDUMP ");
        if (!p) continue;
        p += strlen("ICMPDUMP ");

        char fam[8];
        int len;
        if (sscanf(p, "%7s len=%d", fam, &len) != 2) continue;
        char *hex = strstr(p, "len=");
        if (!hex) continue;
        while (*hex && *hex != ' ') hex++;

        unsigned char buf[MAX_MSG];
        int n = parse_hex(hex, buf, MAX_MSG);
        if (n != len) {
            printf("警告: len=%d と読み取れた %d バイトが一致しません\n", len, n);
        }

        groups++;
        printf("=== %s メッセージ %d (%d バイト) ===\n", fam, groups, n);
        int ok = (strcmp(fam, "v4") == 0) ? check_v4(buf, n)
               : (strcmp(fam, "v6") == 0) ? check_v6(buf, n)
                                          : (printf("  NG: 不明な family\n"), 0);
        printf("  -> %s\n", ok ? "PASS" : "FAIL");
        if (!ok) failures++;
    }

    if (groups == 0) {
        fprintf(stderr, "ICMPDUMP 行が見つかりません(`pmtutest dump` の出力を渡してください)\n");
        return 2;
    }
    printf("\n%d 件中 %d 件が FAIL\n", groups, failures);
    return failures ? 1 : 0;
}
