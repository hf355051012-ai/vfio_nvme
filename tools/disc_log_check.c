/*=================================================================
 * NVMe-oF Discovery Log Page の検証ツール(OptiPlex 上で動かす)。
 *
 * **このリポジトリのコードを一切 include しない。** Linux カーネルの
 * `include/linux/nvme.h` の構造体定義だけを使い、自作ターゲットが返した
 * バイト列をパースして表示する。
 *
 * 狙いは「自作 initiator ↔ 自作 target だけで試すと両側が同じ間違い方を
 * して絶対に検出できない」という穴(CRC32C で実際に踏んだ)を塞ぐこと。
 * 相手側実装が使う構造体そのもので読めることを示せば、自作パーサの
 * 解釈が正しいかとは独立に妥当性を確認できる。
 *
 * 使い方:
 *   1) 自作シェルの `nvmediscover dump` が出す 16 進ダンプをファイルへ保存
 *   2) gcc -o disc_log_check disc_log_check.c
 *   3) ./disc_log_check < dump.txt
 *
 * 入力は 1 行あたり任意個の 16 進バイト(空白区切り、`#` 以降はコメント)。
 * ===============================================================*/
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <ctype.h>

/* ---- include/linux/nvme.h からの引き写し(値・レイアウトを変えないこと) ---- */
#define NVMF_NQN_FIELD_LEN 256
#define NVMF_TRSVCID_SIZE   32
#define NVMF_TRADDR_SIZE   256
#define NVMF_TSAS_SIZE     256

struct nvmf_disc_rsp_page_entry {
    uint8_t  trtype;
    uint8_t  adrfam;
    uint8_t  subtype;
    uint8_t  treq;
    uint16_t portid;
    uint16_t cntlid;
    uint16_t asqsz;
    uint16_t eflags;
    uint8_t  resv10[20];
    char     trsvcid[NVMF_TRSVCID_SIZE];
    uint8_t  resv64[192];
    char     subnqn[NVMF_NQN_FIELD_LEN];
    char     traddr[NVMF_TRADDR_SIZE];
    union tsas {
        char common[NVMF_TSAS_SIZE];
        struct rdma_ {
            uint8_t  qptype;
            uint8_t  prtype;
            uint8_t  cms;
            uint8_t  resv3[5];
            uint16_t pkey;
            uint8_t  resv10[246];
        } rdma;
        struct tcp_ {
            uint8_t sectype;
        } tcp;
    } tsas;
};

struct nvmf_disc_rsp_page_hdr {
    uint64_t genctr;
    uint64_t numrec;
    uint16_t recfmt;
    uint8_t  resv14[1006];
    struct nvmf_disc_rsp_page_entry entries[];
};

static const char *trtype_name(uint8_t v)
{
    switch (v) {
    case 0:   return "PCI";
    case 1:   return "RDMA";
    case 2:   return "FC";
    case 3:   return "TCP";
    case 254: return "LOOP";
    default:  return "??";
    }
}

static const char *adrfam_name(uint8_t v)
{
    switch (v) {
    case 0:   return "PCI";
    case 1:   return "IPv4";
    case 2:   return "IPv6";
    case 3:   return "IB";
    case 4:   return "FC";
    case 254: return "LOOP";
    default:  return "??";
    }
}

static const char *subtype_name(uint8_t v)
{
    switch (v) {
    case 1:  return "Discovery(referral)";
    case 2:  return "NVMe subsystem";
    case 3:  return "Discovery(current)";
    default: return "??";
    }
}

/* NUL 終端されていないかもしれない固定長フィールドを安全に表示する。 */
static void print_field(const char *label, const char *p, size_t n)
{
    size_t len = 0;
    while (len < n && p[len] != '\0') len++;
    printf("  %-8s = \"%.*s\"", label, (int)len, p);
    if (len == n) printf("  [!] NUL 終端されていない");
    printf("\n");
}

int main(void)
{
    static uint8_t buf[1024 * 64];
    size_t n = 0;
    int c;
    unsigned byte = 0;
    int nib = 0;
    int in_comment = 0;

    while ((c = getchar()) != EOF) {
        if (in_comment) {
            if (c == '\n') in_comment = 0;
            continue;
        }
        if (c == '#') { in_comment = 1; continue; }
        if (isxdigit(c)) {
            unsigned v = (unsigned)(isdigit(c) ? c - '0' : (tolower(c) - 'a' + 10));
            byte = (byte << 4) | v;
            if (++nib == 2) {
                if (n >= sizeof(buf)) { fprintf(stderr, "入力が長すぎます\n"); return 1; }
                buf[n++] = (uint8_t)byte;
                byte = 0; nib = 0;
            }
        } else if (nib != 0) {
            fprintf(stderr, "16進が奇数桁です(オフセット %zu 付近)\n", n);
            return 1;
        }
    }

    printf("== 入力 %zu バイト ==\n", n);
    printf("== 構造体オフセット(このホストのコンパイラが決めた値)==\n");
    printf("  hdr: genctr=%zu numrec=%zu recfmt=%zu entries=%zu sizeof=%zu\n",
           offsetof(struct nvmf_disc_rsp_page_hdr, genctr),
           offsetof(struct nvmf_disc_rsp_page_hdr, numrec),
           offsetof(struct nvmf_disc_rsp_page_hdr, recfmt),
           sizeof(struct nvmf_disc_rsp_page_hdr),
           sizeof(struct nvmf_disc_rsp_page_hdr));
    printf("  entry: trsvcid=%zu subnqn=%zu traddr=%zu tsas=%zu sizeof=%zu\n",
           offsetof(struct nvmf_disc_rsp_page_entry, trsvcid),
           offsetof(struct nvmf_disc_rsp_page_entry, subnqn),
           offsetof(struct nvmf_disc_rsp_page_entry, traddr),
           offsetof(struct nvmf_disc_rsp_page_entry, tsas),
           sizeof(struct nvmf_disc_rsp_page_entry));

    if (sizeof(struct nvmf_disc_rsp_page_hdr) != 1024 ||
        sizeof(struct nvmf_disc_rsp_page_entry) != 1024) {
        printf("[!] 構造体サイズが 1024 でない -- パディングが入っている\n");
        return 1;
    }
    if (n < sizeof(struct nvmf_disc_rsp_page_hdr)) {
        printf("[!] NG: ヘッダ(1024バイト)に足りない\n");
        return 1;
    }

    const struct nvmf_disc_rsp_page_hdr *h = (const void *)buf;
    printf("== ヘッダ ==\n");
    printf("  genctr = %llu\n", (unsigned long long)h->genctr);
    printf("  numrec = %llu\n", (unsigned long long)h->numrec);
    printf("  recfmt = %u%s\n", h->recfmt, h->recfmt == 0 ? "" : "  [!] 0 であるべき");

    size_t avail = (n - sizeof(*h)) / sizeof(struct nvmf_disc_rsp_page_entry);
    if (h->numrec > avail) {
        printf("[!] numrec=%llu だが入力には %zu エントリ分しかない\n",
               (unsigned long long)h->numrec, avail);
    }

    int bad = 0;
    for (size_t i = 0; i < h->numrec && i < avail; i++) {
        const struct nvmf_disc_rsp_page_entry *e = &h->entries[i];
        printf("== エントリ %zu ==\n", i);
        printf("  trtype   = %u (%s)\n", e->trtype, trtype_name(e->trtype));
        printf("  adrfam   = %u (%s)\n", e->adrfam, adrfam_name(e->adrfam));
        printf("  subtype  = %u (%s)\n", e->subtype, subtype_name(e->subtype));
        printf("  treq     = %u\n", e->treq);
        printf("  portid   = %u\n", e->portid);
        printf("  cntlid   = 0x%04x%s\n", e->cntlid,
               e->cntlid == 0xFFFF ? " (dynamic)" : "");
        printf("  asqsz    = %u%s\n", e->asqsz,
               e->asqsz < 32 ? "  [!] 32 以上であるべき" : "");
        print_field("trsvcid", e->trsvcid, sizeof(e->trsvcid));
        print_field("subnqn",  e->subnqn,  sizeof(e->subnqn));
        print_field("traddr",  e->traddr,  sizeof(e->traddr));
        if (e->trtype == 3) {
            printf("  sectype  = %u%s\n", e->tsas.tcp.sectype,
                   e->tsas.tcp.sectype == 0 ? " (none)" : "");
        }
        if (e->trtype == 0 || e->trtype > 3) { printf("  [!] trtype が不正\n"); bad = 1; }
        if (e->adrfam != 1 && e->adrfam != 2) { printf("  [!] adrfam が IPv4/IPv6 でない\n"); bad = 1; }
        if (e->subtype != 2 && e->subtype != 3) { printf("  [!] subtype が不正\n"); bad = 1; }
        if (e->subnqn[0] == '\0') { printf("  [!] subnqn が空\n"); bad = 1; }
        if (e->traddr[0] == '\0') { printf("  [!] traddr が空\n"); bad = 1; }
        if (e->trsvcid[0] == '\0') { printf("  [!] trsvcid が空\n"); bad = 1; }
    }

    if (h->numrec == 0) { printf("[!] numrec が 0\n"); bad = 1; }
    if (h->recfmt != 0) bad = 1;
    printf("== 判定: %s ==\n", bad ? "NG" : "PASS(Linux の構造体でそのまま読めた)");
    return bad ? 1 : 0;
}
