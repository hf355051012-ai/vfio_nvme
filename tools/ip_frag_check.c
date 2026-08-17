/*
 * ip_frag_check -- `fragtest dump` が出す断片列を、**このリポジトリのコードを
 * 一切 include せず** Linux の <netinet/ip.h>(struct ip)だけを使って検算する。
 *
 * 自作の送信側と自作の検査側だけで試すと、両者が同じ勘違いをしていても通って
 * しまう(CRC32C で実際に踏んだ穴)。ここでは断片ヘッダを Linux の構造体へ
 * 詰め直し、libc の ntohs / IP_OFFMASK / IP_MF で読み戻して RFC 791 の条件を
 * 確かめる。tools/disc_log_check.c と同じ考え方。
 *
 * ビルド:
 *   gcc -O2 -Wall -Wextra -o /tmp/ip_frag_check tools/ip_frag_check.c
 * 使い方:
 *   fragtest dump の出力を丸ごと標準入力へ流す
 *     ssh rpi5-rdma-target ... | /tmp/ip_frag_check
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/ip.h>   /* struct ip, IP_MF, IP_OFFMASK */
#include <arpa/inet.h>    /* htons/ntohs */

#define MAX_FRAGS 64

struct frag {
    unsigned id, off, len, mf, proto;
};

/*
 * 1 断片ぶんの値から Linux の struct ip を組み立て、ntohs/IP_MF/IP_OFFMASK で
 * 読み戻す。ワイヤ上の 16bit フィールドを一度通すので、「8 バイト単位の
 * オフセットを 13bit に詰める」ところを取り違えていれば必ず食い違う。
 */
static int roundtrip(const struct frag *f, unsigned *out_off, unsigned *out_mf,
                     unsigned *out_total_len)
{
    struct ip h;
    memset(&h, 0, sizeof(h));
    h.ip_hl = 5;
    h.ip_v  = 4;
    h.ip_len = htons((unsigned short)(sizeof(struct ip) + f->len));
    h.ip_id  = htons((unsigned short)f->id);
    /* ここが本題: フラグメントオフセットは 8 バイト単位で 13bit、MF は bit13 */
    unsigned short frag_field = (unsigned short)((f->off / 8u) & IP_OFFMASK);
    if (f->mf) frag_field |= IP_MF;
    h.ip_off = htons(frag_field);
    h.ip_p   = (unsigned char)f->proto;

    if ((f->off % 8u) != 0u) {
        printf("  NG: offset %u が 8 の倍数でない(13bit フィールドに入らない)\n", f->off);
        return -1;
    }
    if ((f->off / 8u) > IP_OFFMASK) {
        printf("  NG: offset %u が 13bit に収まらない\n", f->off);
        return -1;
    }

    unsigned short got = ntohs(h.ip_off);
    *out_off = (got & IP_OFFMASK) * 8u;
    *out_mf  = (got & IP_MF) ? 1u : 0u;
    *out_total_len = ntohs(h.ip_len);
    return 0;
}

int main(void)
{
    char line[512];
    struct frag frags[MAX_FRAGS];
    unsigned n = 0, expect_total = 0, expect_count = 0;
    int saw_header = 0, failures = 0, groups = 0;

    while (fgets(line, sizeof(line), stdin)) {
        char *p = strstr(line, "FRAGDUMP ");
        if (!p) continue;
        p += strlen("FRAGDUMP ");

        unsigned total, count;
        if (sscanf(p, "total=%u count=%u", &total, &count) == 2) {
            if (saw_header) {
                fprintf(stderr, "警告: 前の断片群が閉じていません\n");
            }
            expect_total = total;
            expect_count = count;
            n = 0;
            saw_header = 1;
            continue;
        }

        struct frag f;
        if (sscanf(p, "frag id=%u off=%u len=%u mf=%u proto=%u",
                   &f.id, &f.off, &f.len, &f.mf, &f.proto) == 5) {
            if (!saw_header) {
                fprintf(stderr, "警告: total= 行より前に frag= 行が来ました\n");
                continue;
            }
            if (n < MAX_FRAGS) frags[n++] = f;

            if (n == expect_count) {
                groups++;
                printf("=== 断片群 %d: 期待 total=%u count=%u ===\n",
                       groups, expect_total, expect_count);
                int ok = 1;
                unsigned covered = 0, last = 0;

                for (unsigned i = 0; i < n; i++) {
                    unsigned off, mf, tlen;
                    if (roundtrip(&frags[i], &off, &mf, &tlen) != 0) { ok = 0; continue; }

                    printf("  断片%u: id=%u off=%u len=%u MF=%u total_len=%u",
                           i, frags[i].id, off, frags[i].len, mf, tlen);

                    if (off != frags[i].off || mf != frags[i].mf) {
                        printf("  <- NG(往復で値が変わった)");
                        ok = 0;
                    }
                    if (tlen != frags[i].len + sizeof(struct ip)) {
                        printf("  <- NG(total_len が合わない)");
                        ok = 0;
                    }
                    if (mf && (frags[i].len % 8u) != 0u) {
                        printf("  <- NG(MF=1 なのに長さが 8 の倍数でない)");
                        ok = 0;
                    }
                    if (frags[i].id != frags[0].id) {
                        printf("  <- NG(ID が先頭と違う)");
                        ok = 0;
                    }
                    printf("\n");

                    covered += frags[i].len;
                    if (!mf) {
                        last++;
                        if (off + frags[i].len != expect_total) {
                            printf("  NG: 最終断片の末尾 %u != 期待 %u\n",
                                   off + frags[i].len, expect_total);
                            ok = 0;
                        }
                    }
                }
                if (last != 1) {
                    printf("  NG: MF=0 の断片が %u 個(1 個であるべき)\n", last);
                    ok = 0;
                }
                if (covered != expect_total) {
                    printf("  NG: 長さの合計 %u != 期待 %u\n", covered, expect_total);
                    ok = 0;
                }
                printf("  -> %s\n", ok ? "PASS" : "FAIL");
                if (!ok) failures++;
                saw_header = 0;
            }
        }
    }

    if (groups == 0) {
        fprintf(stderr, "FRAGDUMP 行が見つかりません(`fragtest dump` の出力を渡してください)\n");
        return 2;
    }
    printf("\n%d 群中 %d 群が FAIL\n", groups, failures);
    return failures ? 1 : 0;
}
