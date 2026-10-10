/* iSCSI の CHAP(iscsi_chap.h)。配置と計算は Linux の drivers/target/iscsi/iscsi_target_auth.c
 * (chap_server_compute_hash())と open-iscsi の usr/auth.c から写した。 */
#include "iscsi_chap.h"
#include <string.h>

int iscsi_chap_hash(int alg)
{
    switch (alg) {
    case 5: return CRYPTO_MD5;
    case 6: return CRYPTO_SHA1;
    case 7: return CRYPTO_SHA256;
    case 8: return CRYPTO_SHA3_256;
    default: return -1;
    }
}

int iscsi_chap_num(const char *v, uint32_t vl)
{
    if (vl == 0 || vl > 6) return -1;
    int x = 0;
    for (uint32_t i = 0; i < vl; i++) {
        if (v[i] < '0' || v[i] > '9') return -1;
        x = x * 10 + (v[i] - '0');
    }
    return x;
}

int iscsi_chap_pick(const char *list, uint32_t len)
{
    uint32_t i = 0;
    while (i < len) {
        uint32_t j = i;
        while (j < len && list[j] != ',') j++;
        const int a = iscsi_chap_num(&list[i], j - i);
        if (iscsi_chap_hash(a) >= 0) return a;
        i = j + 1u;
    }
    return -1;
}

uint32_t iscsi_chap_response(int alg, uint8_t id, const uint8_t *secret, uint32_t slen,
                             const uint8_t *chal, uint32_t clen, uint8_t *out)
{
    const int h = iscsi_chap_hash(alg);
    if (h < 0) return 0;
    crypto_hash_ctx_t c;
    if (crypto_hash_init(&c, (crypto_hash_id_t)h) != 0) return 0;
    crypto_hash_update(&c, &id, 1);
    crypto_hash_update(&c, secret, slen);
    crypto_hash_update(&c, chal, clen);
    crypto_hash_final(&c, out);
    return (uint32_t)crypto_hash_len((crypto_hash_id_t)h);
}

static int hexval(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int iscsi_chap_decode(const char *v, uint32_t vl, uint8_t *out, uint32_t cap)
{
    if (vl < 3 || v[0] != '0') return -1;
    if (v[1] == 'x' || v[1] == 'X') {
        const char *p = v + 2;
        uint32_t n = vl - 2u, o = 0;
        if (n & 1u) {   /* 奇数桁は先頭に 0 を補う */
            const int d = hexval(p[0]);
            if (d < 0 || o >= cap) return -1;
            out[o++] = (uint8_t)d;
            p++; n--;
        }
        for (uint32_t i = 0; i < n; i += 2) {
            const int a = hexval(p[i]), b = hexval(p[i + 1]);
            if (a < 0 || b < 0 || o >= cap) return -1;
            out[o++] = (uint8_t)(a << 4 | b);
        }
        return (int)o;
    }
    if (v[1] == 'b' || v[1] == 'B') return crypto_base64_decode(v + 2, vl - 2u, out, cap);
    return -1;
}

void iscsi_chap_hex(const uint8_t *b, uint32_t n, char *out)
{
    static const char H[] = "0123456789abcdef";
    out[0] = '0';
    out[1] = 'x';
    for (uint32_t i = 0; i < n; i++) {
        out[2 + 2 * i] = H[b[i] >> 4];
        out[3 + 2 * i] = H[b[i] & 15];
    }
    out[2 + 2 * n] = 0;
}
