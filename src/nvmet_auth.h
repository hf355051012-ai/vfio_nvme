#ifndef NVMET_AUTH_H
#define NVMET_AUTH_H

/* NVMe in-band 認証(DH-HMAC-CHAP)のコントローラ側(PLAN_auth_tls.md 段階 A)。
 *
 * Fabrics の Authentication Send(fctype 0x05)/ Receive(0x06)で運ぶ
 * メッセージを解釈して、ホストが鍵を知っているかを確かめる。
 * **トランスポートに依存しない**(TCP / RDMA のどちらの admin 経路からも呼ぶ)。
 *
 * 手本は Linux の drivers/nvme/target/fabrics-cmd-auth.c と target/auth.c
 * (OptiPlex の ~/rpi-kbuild/src、6.18)。メッセージの配置は include/linux/nvme.h。
 * Linux と同じく**認証するのは admin キューだけ**(IO キューの Connect には
 * ATR を立てない。`nvmet_connect_result()` の "Do not authenticate I/O queues")。
 *
 * 段階 A: DH 群 NULL・片方向。段階 B: ffdhe2048〜8192 と双方向(コントローラの鍵で R2 を返す)。
 */

#include <stdint.h>

/* CQE の status ワード(Linux の NVME_SC_* を 1 ビット左へ寄せた値。nvmet.c と同じ流儀)。 */
#define NVMET_AUTH_SC_AUTH_REQUIRED  0x8322u   /* SCT=1 SC=0x91 Authentication Required + DNR */
#define NVMET_AUTH_SC_INVALID_HOST   0x8308u   /* SCT=1 SC=0x84 Connect Invalid Host + DNR */
#define NVMET_AUTH_SC_INVALID_FIELD  0x8004u   /* SC=0x02 Invalid Field in Command + DNR */

/* Connect の応答(dw0)に立てる「認証が要る」(NVME_CONNECT_AUTHREQ_ATR)。 */
#define NVMET_AUTH_CONNECT_ATR       (1u << 17)

#define NVMET_AUTH_NQN_MAX           256u
/* Authentication Receive の最大長(Linux のホストは 4096 を入れてくる)。 */
#define NVME_AUTH_RECV_BYTES         4096u

/* admin キュー 1 本ぶん(= 1 セッション)の認証の状態。 */
typedef struct {
    uint8_t  required;        /* このセッションは認証が済むまで他のコマンドを受けない */
    uint8_t  authenticated;
    uint8_t  failed;          /* Failure を返した / 受けた。以後は何も受けない */
    uint8_t  step;            /* 次に期待するメッセージ(NVME_AUTH_DHCHAP_MESSAGE_*)*/
    uint8_t  status;          /* Failure1 に入れる理由(rescode_exp)*/
    uint8_t  hashid;          /* 合意したハッシュ(1/2/3)*/
    uint8_t  dhgid;           /* 合意した DH 群(段階 A は 0 = NULL のみ)*/
    uint8_t  sc_c;            /* Negotiate の SC_C(secure channel concatenation)*/
    uint8_t  concat_ok;       /* このトランスポートで concatenation できる(TCP = 1、RDMA = 0)*/
    uint8_t  queue_tls;       /* このキューは TLS で繋がっている */
    uint8_t  concat;          /* このセッションは concatenation(認証が済んだら PSK を生成する)*/
    uint16_t tid;             /* トランザクション ID(T_ID)*/
    uint32_t s1;              /* Challenge に入れた通し番号 */
    uint8_t  c1[64];          /* Challenge に入れた乱数 */
    /* 双方向(ホストもコントローラを確かめる)。Reply の S2 / C2 を控え、
     * Success1 で R2 を返し、Success2 を受けて初めて認証済みにする。 */
    uint8_t  bidir;
    uint32_t s2;
    uint8_t  c2[64];
    /* DH 群(段階 B)。秘密の指数は共有秘密を作ったら消す。共有秘密は
     * 素数の長さ(最大 1024 バイト)に 0 詰めしたまま持つ。 */
    uint8_t  dh_priv[64];
    uint8_t  skey[1024];
    uint32_t skey_len;
    char     hostnqn[NVMET_AUTH_NQN_MAX + 1];
} nvmet_auth_sess_t;

/* 鍵が設定されているか(= 通常のサブシステムへの接続に認証を求めるか)。 */
int nvmet_auth_enabled(void);

/* admin の Connect(qid=0)を受けたときに呼ぶ。hostnqn は Connect データの
 * offset 512 の 256 バイト。戻り値は 0 = 受理(応答 dw0 に *atr を OR する)、
 * それ以外 = Connect に返す status(設定外のホスト)。 */
uint16_t nvmet_auth_on_connect(nvmet_auth_sess_t *s, const uint8_t *hostnqn256, uint32_t *atr);

/* NVMe/TCP の admin の Connect(段階 H)。concatenation を受けられ、**TLS で繋がった
 * キューには認証を求めない**(Linux の nvmet_has_auth() = 鍵があり、かつ TLS でないとき)。 */
uint16_t nvmet_auth_on_connect_tcp(nvmet_auth_sess_t *s, const uint8_t *hostnqn256, uint32_t *atr,
                                   int queue_tls);

/* 認証が済むまで受けてはいけないコマンドか。1 = 拒否する。 */
int nvmet_auth_blocks(const nvmet_auth_sess_t *s);

/* Authentication Send。sqe の cdw10(SECP / SPSP0 / SPSP1)と cdw11(TL)、
 * 受け取ったデータ。戻り値は CQE の status(0 = 成功)。 */
uint16_t nvmet_auth_send(nvmet_auth_sess_t *s, uint32_t cdw10, uint32_t cdw11,
                         const uint8_t *data, uint32_t dlen, const char *subnqn);

/* Authentication Receive。out に cdw11(AL)バイトぶんを作る(足りない部分は 0)。
 * *out_len に送るバイト数を返す。戻り値は CQE の status。 */
uint16_t nvmet_auth_receive(nvmet_auth_sess_t *s, uint32_t cdw10, uint32_t cdw11,
                            uint8_t *out, uint32_t cap, uint32_t *out_len, const char *subnqn);

void nvmet_auth_reset(nvmet_auth_sess_t *s);

/* シェルの `nvmetauth ...`。 */
void nvmet_auth_shell(const char *args);

#endif /* NVMET_AUTH_H */
