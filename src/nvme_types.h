#ifndef NVME_TYPES_H
#define NVME_TYPES_H

#include <stdint.h>

/* ================================================================
 * nvme_types.h — NVMe Base Specification の構造体定義のみ
 * (SQE/CQE/SGLディスクリプタ)。プロトコルロジックはnvme.cが持つ —
 * ここには構造体とオペコード定数のみを置く。
 *
 * 全フィールドはリトルエンディアン(net.hのrd16le/rd32le/rd64le/wr16le/
 * wr32le/wr64le経由でのみアクセスすること -- 直接の多バイトアクセスは
 * 禁止。理由はnet.hの当該コメント参照)。
 * ================================================================ */

/* SQE (Submission Queue Entry) — 全コマンド共通の64バイト固定フォーマット
 * (Linuxのstruct nvme_common_commandと同じレイアウト)。
 * cdw0: opcode[7:0] flags[15:8](fuse[1:0] psdt[5:4]) cid[31:16]
 * nsid/reserved1/reserved2/mptr/dptr/cdw10-15の各オフセットは64バイト中
 * 固定 -- NVMe-oF Fabricsコマンド(Connect等)もこの同じ64バイト構造の
 * 中に自分のフィールドをオーバーレイする(nsidの下位バイトがfctype、
 * cdw10-15がrecfmt/qid/sqsize/cattr/kato、というように — nvme.c参照)。 */
/* cdw0のflagsバイト(byte1)のPSDTフィールド(bits[7:6])。00b=PRP,
 * 01b=SGL(MPTRが単一の連続物理バッファのアドレス)、10b=SGL(MPTRがSGL
 * segmentのアドレス)。NVMe-oF(Fabrics)トランスポートはPRPを一切使わず
 * 常にSGLのみを使うため、この値(01b、すなわちbit6=1)を全コマンドの
 * cdw0へ必ず設定すること -- 設定を忘れるとnvmet側のnvmet_req_init()が
 * `(flags & NVME_CMD_SGL_ALL) != NVME_CMD_SGL_METABUF`のチェック
 * (NVME_CMD_SGL_METABUF=1<<6=0x40、include/linux/nvme.h)で静かに
 * コマンドを拒否する(実機のnvmet-tcpとの相互接続検証で確認、
 * "nvmet_tcp: failed cmd ... opcode NN, data_len: NN"としてdmesgに残る
 * だけでNVMe/TCPレベルの応答は一切返らない)。当初bits[5:4]だと誤って
 * 実装し0x10を使っていたが、実際のビット位置はbits[7:6]でNVME_CMD_
 * SGL_METABUFの値は0x40 -- カーネルソース(上記)で確認済み。 */
#define NVME_PSDT_SGL_MPTR_CONTIGUOUS 0x40u

typedef struct __attribute__((packed)) {
    uint32_t cdw0;
    uint32_t nsid;
    uint32_t reserved1;
    uint32_t reserved2;
    uint64_t mptr;
    uint8_t  dptr[16];   /* SGL1 (nvme_sgl_desc_t が16バイトそのまま入る) */
    uint32_t cdw10;
    uint32_t cdw11;
    uint32_t cdw12;
    uint32_t cdw13;
    uint32_t cdw14;
    uint32_t cdw15;
} nvme_sqe_t;

#define NVME_SQE_LEN 64u

/* CQE (Completion Queue Entry) — 16バイト固定フォーマット。 */
typedef struct __attribute__((packed)) {
    uint32_t dw0;
    uint32_t dw1;
    uint16_t sq_head;
    uint16_t sq_id;
    uint16_t cid;
    uint16_t status;   /* bit0 = phase tag, bits[15:1] = status code + type */
} nvme_cqe_t;

#define NVME_CQE_LEN 16u

/* statusフィールドからphase tagを除いた実ステータス値(SCT+SC)を取り出す。
 * status自体はnet.hのrd16le経由で読んだ後のローカル値を渡す前提
 * (packed構造体への直接アクセスではないためvolatile不要)。 */
static inline uint16_t nvme_cqe_status_code(uint16_t status) { return (uint16_t)(status >> 1); }
static inline int      nvme_cqe_phase(uint16_t status) { return status & 1; }

/* SGLディスクリプタ(16バイト、NVMe Base Spec Figure参照)。
 * NVMe/TCPでは実メモリアドレスを転送するわけではなく、addrは常に0。
 * typeは下記2種類を使い分ける(実機のnvmet-tcpとの相互接続検証で確定 --
 * 詳細はNVME_SGL_TYPE_*のコメント参照)。 */
typedef struct __attribute__((packed)) {
    uint64_t addr;
    uint32_t len;
    uint8_t  reserved[3];
    uint8_t  type;      /* [7:4]=SGL Descriptor Type [3:0]=SGL Descriptor Subtype */
} nvme_sgl_desc_t;

/* (0x0<<4)|0x1: Data Block descriptor, Offset subtype -- 「in-capsule
 * データ(このPDU自身に続けて到着済み)」を示す型。**書き込みコマンドで
 * 実際にデータをin-capsule送信する場合のみ使うこと** -- nvme_tcp.cの
 * nvme_tcp_send_cmd()がこの型のときデータをCommand Capsule PDUの
 * 固定部(72B)に続けて実際に書き込み、hdr.pdo/hdr.plenをそれに合わせて
 * 設定する責務を負う。型だけこれにしてデータを実際には付加しない
 * (以前試したR2T+H2CData前提の実装)と、target側のnvmet_tcp_map_data()が
 * 「in-capsuleデータが来るはず」と解釈してTCPストリームからの続きの
 * 読み込みでブロックし、こちらはtargetからのR2Tを待ってブロックする --
 * 双方向デッドロックを実機で確認済み。 */
#define NVME_SGL_TYPE_DATA_BLOCK_OFFSET 0x01u

/* (0x5<<4)|0xA: Transport SGL Data Block descriptor, Transport-specific
 * subtype A -- 読み出しコマンド(C2HDataで応答が返る)、およびデータを
 * 一切伴わないコマンド(Set Features等、値はcdw10-15に収まる)で使う型。
 * Linuxのnvme_tcp_set_sg_host_data()/nvme_tcp_set_sg_null()
 * (drivers/nvme/host/tcp.c)と同一の値(型バイトはこの2関数で共通)。
 * 単独では(データを実際に転送せずR2Tを待つだけの実装で)Connectコマンドに
 * 使った際も実機のnvmet-tcpに対してデッドロックした(上記と対称的な
 * 問題、テスト過程で確認) -- 書き込みには使わないのがこの型の正しい
 * 使い方。 */
#define NVME_SGL_TYPE_TRANSPORT 0x5Au

/* Keyed SGL Data Block descriptor(16バイト)。ConnectX RoCEv2 NVMe-oF
 * 実装計画(~/.claude/plans/peppy-wobbling-lamport.md)フェーズ(g)、
 * nvme_rdma.c/nvmet_rdma.c(RDMAトランスポート)専用 -- TCPのnvme_sgl_
 * desc_tとは違いaddrが実際にリモートDMAアドレスとして使われ、rkey交換の
 * ためlength/keyフィールドを持つ。include/linux/nvme.hのstruct nvme_
 * keyed_sgl_desc(このセッションで実際に取得して確認済み)と同一レイアウト:
 * addr(8B LE)+length(3B LE、24bit)+key(4B LE、rkey=mlx5のmkey値そのもの)+
 * type(1B)。lengthが3バイト(4バイトではない)点に注意 -- 素朴なuint32_tの
 * フィールドとしては表現できないためbyte配列にしてある。typeの値は
 * drivers/nvme/host/rdma.cのnvme_rdma_set_sg_null()/nvme_rdma_map_sg_
 * single()で確認済み: (NVME_KEY_SGL_FMT_DATA_DESC(0x04)<<4)|0 = 0x40。 */
#define NVME_SGL_TYPE_KEYED_DATA_BLOCK 0x40u

typedef struct __attribute__((packed)) {
    uint64_t addr;
    uint8_t  length[3];
    uint8_t  key[4];
    uint8_t  type;
} nvme_keyed_sgl_desc_t;
_Static_assert(sizeof(nvme_keyed_sgl_desc_t) == 16, "must match nvme_sqe_t.dptr[16]");

/* 書き込みコマンド(Fabrics Connect含む)のデータをin-capsule送信できる
 * 上限。NVMe-oF/TCPの実装(drivers/nvme/host/tcp.cのNVME_TCP_ADMIN_CCSZ)
 * がFabricsコマンドのin-capsule上限として8KiBを使っているのに合わせた
 * 値。Connect data(1024B)やこのプロジェクトのshellコマンド`nvme write`の
 * 上限(512B)はいずれもこれ以下でin-capsuleのまま送られる。
 *
 * これを超える書き込みはR2T+H2CData経由の分割送信になる(2026-08-08、
 * R2T分割実装 -- 以前はこれを超えるとエラーにしていた、nvme.cの
 * nvme_build_write_sqe()/nvme_tcp.cのnvme_tcp_send_cmd()参照)。 */
#define NVME_TCP_INLINE_DATA_MAX 8192u

/* Controller Configuration(CC)/Controller Status(CSTS)レジスタは
 * PCIe接続ではBAR経由のメモリマップドレジスタだが、NVMe-oF(Fabrics)
 * トランスポートではFabrics Property Set/Getコマンドで読み書きする
 * 「プロパティ」として同じ意味を持つ -- Fabrics Connect直後は
 * CC.EN=0(無効)の状態でコントローラが生成され、Identify等の通常の
 * Admin/IOコマンドは一切受け付けない(実機のnvmet-tcpで
 * "got cmd 6 while CC.EN == 0 on qid = 0"というログと共に拒否される
 * ことを確認済み -- 当初この有効化シーケンスの実装自体を見落としていた)。
 * オフセットはNVMe Base Spec Figure "Controller Properties"。 */
#define NVME_REG_CAP  0x00u  /* Controller Capabilities (8バイト) */
#define NVME_REG_VS   0x08u  /* Version (4バイト) */
#define NVME_REG_CC   0x14u  /* Controller Configuration (4バイト) */
#define NVME_REG_CSTS 0x1Cu  /* Controller Status (4バイト) */

/* CCフィールド(include/linux/nvme.hのenum定義で確定 -- 特にIOSQES/IOCQES
 * を標準値(64B/16B, 本実装のnvme_sqe_t/nvme_cqe_tと一致)に設定しないと、
 * target側のnvmet_start_ctrl()がCSTS.CFS(Controller Fatal Status)へ
 * 落としてしまい、CC.EN=1書き込み自体は成功したように見えるのに以後の
 * コマンドが機能しない -- 実機検証で発見。MPS=0(4KiBページ、本実装は
 * メモリマップドDMAを行わないため実質無関係だが規定値として必要)、
 * AMS=0(Round Robin)、CSS=0(NVM Command Set)も同様に規定値を明示する。 */
#define NVME_CC_EN       0x00000001u
#define NVME_CC_CSS_NVM  0x00000000u
#define NVME_CC_AMS_RR   0x00000000u
#define NVME_CC_SHN_NONE 0x00000000u
#define NVME_CC_IOSQES   (6u << 16)  /* 2^6 = 64バイト、nvme_sqe_tと一致 */
#define NVME_CC_IOCQES   (4u << 20)  /* 2^4 = 16バイト、nvme_cqe_tと一致 */

#define NVME_CSTS_RDY 0x00000001u
#define NVME_CSTS_CFS 0x00000002u  /* Controller Fatal Status */

/* Admin Command Set オペコード(NVMe Base Spec)。 */
#define NVME_ADM_CMD_DELETE_SQ     0x00u
#define NVME_ADM_CMD_CREATE_SQ     0x01u
#define NVME_ADM_CMD_DELETE_CQ     0x04u
#define NVME_ADM_CMD_CREATE_CQ     0x05u
#define NVME_ADM_CMD_IDENTIFY      0x06u
#define NVME_ADM_CMD_SET_FEATURES  0x09u
#define NVME_ADM_CMD_GET_FEATURES  0x0Au
#define NVME_ADM_CMD_KEEP_ALIVE    0x18u

/* NVM Command Set (IO queue) オペコード。 */
#define NVME_IO_CMD_FLUSH  0x00u
#define NVME_IO_CMD_WRITE  0x01u
#define NVME_IO_CMD_READ   0x02u

/* NVMe-oF Fabrics コマンド。opcode=0x7Fは両方のキュー種別(admin/IO)で
 * 共通の「Fabricsコマンド」を示し、実際の種別はfctype(nsidフィールドの
 * 下位バイトにオーバーレイされる、nvme.c参照)で決まる。 */
#define NVME_FABRIC_CMD                  0x7Fu
#define NVME_FABRIC_FCTYPE_PROPERTY_SET  0x00u
#define NVME_FABRIC_FCTYPE_CONNECT       0x01u
#define NVME_FABRIC_FCTYPE_PROPERTY_GET  0x04u

/* Identify command の cdw10 下位バイト(CNS: Controller or Namespace Structure)。 */
#define NVME_IDENTIFY_CNS_NAMESPACE   0x00u
#define NVME_IDENTIFY_CNS_CONTROLLER  0x01u

/* Identify Namespace データ構造(4096バイトのうち、lba_size算出に必要な
 * 部分のみ抜粋 -- 残りはnvme.cが呼び出し側にそのまま返す)。
 * flbas[2:0] が LBA Format Index、lbaf[flbas].ds が2^dsバイトのLBAサイズ。 */
#define NVME_ID_NS_OFF_FLBAS   26u   /* offset within the 4096B Identify Namespace buffer */
#define NVME_ID_NS_OFF_LBAF0   128u  /* LBA Format 0 descriptor offset (4 bytes each) */

typedef struct __attribute__((packed)) {
    uint16_t ms;   /* metadata size */
    uint8_t  ds;   /* LBA data size, reported as a power of 2 */
    uint8_t  rp;   /* relative performance */
} nvme_lbaf_t;

#endif /* NVME_TYPES_H */
