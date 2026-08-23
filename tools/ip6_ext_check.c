/*
 * ip6_ext_check -- `ext6test dump` が出す IPv6 拡張ヘッダのバイト列を、
 * **このリポジトリのコードを一切 include せず** glibc の構造体だけで読み直す。
 *
 *   <netinet/ip6.h> の struct ip6_hbh / ip6_dest / ip6_rthdr / ip6_frag
 *
 * **拡張ヘッダは「長さの数え方」を取り違えやすい。** 長さは 8 オクテット単位
 * で、しかも**最初の 8 バイトを含まない**(= (len + 1) * 8)。Fragment だけは
 * 8 バイト固定で長さフィールドを持たず、代わりに 2-3 バイト目が
 * 「オフセット(上位 13bit)+ 予約 2bit + More(最下位 1bit)」になる。
 * これらを自作の注入側と自作の受信側だけで試すと、**両方が同じ間違い方を
 * して素通りする**(CRC32C / NDP の Target Address / MLD のレコード数で
 * 実際に踏んだ穴)。
 *
 * なお **送信側の断片化そのものは Linux に再構成させて確認済み**
 * (tools/udp6_echo.py)。このツールが担当するのは、`ext6test` が注入する
 * 拡張ヘッダの形式が正しいことの検算。
 *
 * ビルド:
 *   gcc -O2 -Wall -Wextra -o /tmp/ip6_ext_check tools/ip6_ext_check.c
 * 使い方:
 *   ext6test dump の出力を標準入力へ流す
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <arpa/inet.h>

_Static_assert(sizeof(struct ip6_frag) == 8, "Fragment ヘッダは 8 バイト固定");
_Static_assert(offsetof(struct ip6_frag, ip6f_offlg) == 2, "offset+flags は byte 2-3");
_Static_assert(offsetof(struct ip6_frag, ip6f_ident) == 4, "identification は byte 4-7");
_Static_assert(offsetof(struct ip6_rthdr, ip6r_segleft) == 3, "segments left は byte 3");

/* 自作側の next header 番号(Linux の NEXTHDR_* と同じ値)。 */
#define NH_HOP 0
#define NH_RT  43
#define NH_FRG 44
#define NH_DST 60
#define NH_UDP 17

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

static int check_opts(const unsigned char *buf, int len, const char *what)
{
    /* Hop-by-Hop / Destination Options: nxt(0) len(1) の後ろに TLV が並ぶ。
     * **PAD1(type 0)だけ長さフィールドを持たない。** */
    int ok = 1;
    int total = (buf[1] + 1) * 8;
    printf("  %s: next=%u len=%u(= %d バイト)\n", what, buf[0], buf[1], total);
    if (total != len) {
        printf("  NG: 長さフィールドから求めた %d バイトと実際の %d が違う"
               "(最初の 8 バイトを含めて数えていないか)\n", total, len);
        return 0;
    }
    int p = 2;
    while (p < len) {
        unsigned t = buf[p];
        if (t == 0) { printf("    option PAD1\n"); p += 1; continue; }
        if (p + 2 > len) { printf("  NG: オプションが途中で切れている\n"); return 0; }
        unsigned olen = buf[p + 1];
        const char *act = ((t & 0xC0) == 0x00) ? "読み飛ばす"
                        : ((t & 0xC0) == 0x40) ? "破棄"
                        : ((t & 0xC0) == 0x80) ? "破棄+ICMP" : "破棄+ICMP(非マルチキャストのみ)";
        printf("    option type=0x%02x len=%u  未知なら:%s\n", t, olen, act);
        if (p + 2 + (int)olen > len) {
            printf("  NG: オプション長がヘッダ末尾を越える\n");
            ok = 0;
            break;
        }
        p += 2 + (int)olen;
    }
    return ok;
}

static int check_ext(const unsigned char *buf, int len, int nh)
{
    if (len < 8) {
        printf("  NG: 拡張ヘッダが 8 バイト未満 (%d)\n", len);
        return 0;
    }
    switch (nh) {
    case NH_HOP:  return check_opts(buf, len, "Hop-by-Hop");
    case NH_DST:  return check_opts(buf, len, "Destination Options");
    case NH_RT: {
        struct ip6_rthdr r;
        memcpy(&r, buf, sizeof(r));
        int total = (r.ip6r_len + 1) * 8;
        printf("  Routing: next=%u len=%u(= %d バイト)type=%u segments_left=%u\n",
               r.ip6r_nxt, r.ip6r_len, total, r.ip6r_type, r.ip6r_segleft);
        if (total != len) {
            printf("  NG: 長さフィールドと実際の長さが違う\n");
            return 0;
        }
        /* RFC 5095 で Routing Type 0 は廃止。segments_left != 0 なら受信側は
         * 破棄しなければならない(このツールは注記だけ -- 破棄するのは
         * 受信側の責任で、ext6test [4] が確認する)。 */
        if (r.ip6r_type == 0 && r.ip6r_segleft != 0) {
            printf("  注記: Type 0 かつ segments_left!=0 -- 受信側は破棄すべき"
                   "(RFC 5095)\n");
        }
        return 1;
    }
    case NH_FRG: {
        struct ip6_frag f;
        memcpy(&f, buf, sizeof(f));
        /* **glibc の IP6F_* はネットワークバイト順のまま掛ける定数**
         * (リトルエンディアンでは IP6F_OFF_MASK=0xf8ff)。ntohs() した値へ
         * 掛けると壊れる -- このツールを書いたときに実際に間違え、正しい
         * 実装を「オフセットが 8 の倍数でない」と誤って NG にした。 */
        unsigned off   = ntohs(f.ip6f_offlg & IP6F_OFF_MASK);
        unsigned more  = (f.ip6f_offlg & IP6F_MORE_FRAG) ? 1 : 0;
        unsigned resv  = (f.ip6f_offlg & IP6F_RESERVED_MASK) ? 1 : 0;
        printf("  Fragment: next=%u offset=%u(バイト)more=%u ident=0x%08x\n",
               f.ip6f_nxt, off, more, ntohl(f.ip6f_ident));
        int ok = 1;
        if (len != 8) {
            printf("  NG: Fragment ヘッダは 8 バイト固定なのに %d\n", len);
            ok = 0;
        }
        if (f.ip6f_reserved != 0) {
            printf("  NG: reserved(byte 1)は 0 でなければならない\n");
            ok = 0;
        }
        if (resv) {
            printf("  NG: offset の予約 2bit が 0 でない"
                   "(バイトオフセットをそのまま入れていないか)\n");
            ok = 0;
        }
        if (off % 8u != 0u) {
            printf("  NG: オフセットが 8 の倍数でない\n");
            ok = 0;
        }
        return ok;
    }
    default:
        printf("  NG: 拡張ヘッダではない next header=%d\n", nh);
        return 0;
    }
}

int main(void)
{
    char line[4096];
    int groups = 0, failures = 0;

    printf("=== glibc の定義(自作側の定数はこれと一致すべき)===\n");
    printf("  struct ip6_frag   = %zu バイト、offlg は offset %zu、ident は %zu\n",
           sizeof(struct ip6_frag), offsetof(struct ip6_frag, ip6f_offlg),
           offsetof(struct ip6_frag, ip6f_ident));
    printf("  IP6F_OFF_MASK=0x%04x IP6F_MORE_FRAG=0x%04x"
           "(**ネットワーク順のまま掛ける定数**。ntohs 後に掛けてはいけない)\n",
           (unsigned)IP6F_OFF_MASK, (unsigned)IP6F_MORE_FRAG);
    printf("  struct ip6_rthdr  = %zu バイト、segments_left は offset %zu\n\n",
           sizeof(struct ip6_rthdr), offsetof(struct ip6_rthdr, ip6r_segleft));

    while (fgets(line, sizeof(line), stdin)) {
        char *p = strstr(line, "EXT6DUMP ");
        if (!p) continue;
        p += strlen("EXT6DUMP ");

        int kind, nh, len;
        if (sscanf(p, "kind=%d nh=%d len=%d", &kind, &nh, &len) != 3) continue;
        char *hex = strstr(p, "len=");
        if (!hex) continue;
        while (*hex && *hex != ' ') hex++;

        unsigned char buf[64];
        int n = parse_hex(hex, buf, (int)sizeof(buf));
        if (n != len) {
            printf("警告: len=%d と読み取れた %d バイトが一致しません\n", len, n);
        }

        groups++;
        printf("=== 拡張ヘッダ %d (kind=%d, next header=%d, %d バイト) ===\n",
               groups, kind, nh, n);
        int ok = check_ext(buf, n, nh);
        printf("  -> %s\n", ok ? "OK" : "NG");
        if (!ok) failures++;
    }

    if (groups == 0) {
        printf("EXT6DUMP 行が 1 つも見つかりませんでした"
               "(`ext6test dump` の出力を流してください)\n");
        return 2;
    }
    printf("\n%d 個中 %d 個が NG -> %s\n", groups, failures, failures ? "FAIL" : "PASS");
    return failures ? 1 : 0;
}
