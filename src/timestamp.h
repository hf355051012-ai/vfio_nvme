#ifndef TIMESTAMP_H
#define TIMESTAMP_H

#include <stdint.h>

/* ================================================================
 * timestamp.h — 性能分析用の軽量タイムスタンプロガー。
 *
 * timer_now()(ARMv8ジェネリックタイマー、timer.h)の値をtag/argと共に
 * 64バイト固定長エントリでリングバッファに記録する。ts_log()自体は
 * UART出力等を一切行わず生の値を書くだけなので呼び出しコストが低く、
 * ホットパスに直接埋め込んで使える -- 記録した内容は後でまとめて
 * ts_log_dump_core()でUARTへデコード表示する(コマンド`ts`、command.c参照)。
 *
 * tag は TS_MK(TS_FILE_*, TS_FUNC_*, info) で組み立てる
 * (bit[31:24]=File#、bit[23:16]=Func#、bit[15:0]=info=同一関数内の通し
 * 番号、下記マクロ参照)。ts_log_dump_core() が File名:Func名#info を
 * 表示するので、どのファイルのどの関数の何番目の記録かが一目で分かる。
 * arg はその呼び出しが記録したい実値(バイト数・conn_slot 等)。
 * 絞り込みは `ts mask <mask> <value>`((tag & mask)==value)で行う。
 *
 * マルチコア化 Phase 3(~/.claude/plans/wondrous-baking-gadget.md参照)で
 * per-core化した: リングバッファ・累計カウンタ・一時停止フラグ・
 * フリーズバッファをすべてコアごとに独立配列化し(timestamp.c
 * 参照)、smp.hのsmp_core_index()で実行中のコアの配列だけを読み書きする
 * ため、以前の「単一コア前提でロック無し」設計をそのまま維持できている
 * -- 同一配列への複数コアからの競合書き込みが構造的に起きないので、
 * ロックは依然として不要。呼び出し側(ts_log()等)のシグネチャは一切
 * 変えていない -- 「どのコアの記録か」は呼び出し元ではなく実行中の
 * コアが暗黙に決める。ts_log_dump_core()等のダンプ系関数も同様に「呼び出した
 * コア自身の記録」だけを表示する(通常はcore0のシェルから呼ぶため、
 * 従来通りcore0の記録が見える)。
 * ================================================================ */

/* リングバッファ総サイズ。1MBという値自体は変更前から確保している
 * RAM予算で、エントリを16→64バイトへ拡張した今回もそのまま据え置く
 * (総バイト数を増やす理由が無いため) -- エントリ数だけが65536→16384
 * に縮小する(2のべき乗のまま、インデックス計算はマスクだけで済む)。 */
#define TS_LOG_BYTES        (1024u * 1024u)
#define TS_LOG_ENTRY_BYTES  64u
#define TS_LOG_COUNT        (TS_LOG_BYTES / TS_LOG_ENTRY_BYTES)

/* エントリが記録している内容がどの記録関数由来かを示す(kindフィールド)。
 * plain(ts_log())以外のkindでは、その記録関数が触らないフィールドは
 * すべて0クリアされる(呼び出し元が読む必要があるのはkindに対応する
 * フィールド群だけ)。 */
#define TS_KIND_PLAIN     0u  /* ts_log(): tag/argのみ有効 */
#define TS_KIND_NVME_PDU  1u  /* ts_log_nvme_tcp_pdu(): PDU系フィールドが有効 */
#define TS_KIND_TCP_ACK   2u  /* ts_log_tcp_ack(): TCP系フィールドが有効 */
#define TS_KIND_RDMA      3u  /* ts_log_rdma(): ConnectX SQ/RQ WQE投稿・CQE消費系フィールドが有効 */

/* 1件のタイムスタンプエントリ(ちょうど64バイト、暗黙のコンパイラ
 * パディングに頼らずフィールドを自然アラインな順序で並べて過不足なく
 * 64バイトになるよう設計 -- 末尾pad[5]で調整。sizeof(ts_entry_t) ==
 * TS_LOG_ENTRY_BYTES はtimestamp.cの_Static_assertで保証する)。
 *
 * pdu_type/hlen/pdo/pdu_lenはNVMe/TCP PDUの共通ヘッダ(CH、nvme_tcp_pdu.hの
 * nvme_tcp_hdr_t参照、全PDU種別で常に有効)。opcode/cid/cccid/status/
 * sgl_type/data_offset/data_length/ttagはPDU種別ごとのペイロード固有
 * ヘッダ(PSH)向けで、pdu_typeに応じて意味が変わる(ts_log_nvme_tcp_pdu()の
 * ドキュメント、ts_nvme_pdu_t参照) -- 未使用の組み合わせは0のまま。
 * tcp_seq/tcp_ack_seq/tcp_window/tcp_flagsはTCP ACK/Window Update向け。
 * pdu_typeの値自体はここで独自enumを定義せず、nvme_tcp_pdu.hの
 * NVME_TCP_PDU_*定数をそのまま渡すこと(値の重複定義は、値がずれた場合に
 * 気付けないまま食い違う実例になりかねないため避ける)。
 *
 * kind==TS_KIND_RDMA(2026-08-12追加、ts_log_rdma()/ts_rdma_t参照)では、
 * 同じ64バイトの器を以下のように読み替える(新規フィールドは追加せず
 * NVMe/TCP PDU用の既存フィールドを流用する -- サイズを変えないため):
 *   pdu_type    = TS_RDMA_OP_*(SQ_SEND/SQ_RDMA_WRITE/SQ_RDMA_READ/RQ_POST/
 *                 CQE/CQE_ERR、switchで表示形式を選ぶ役割はNVMe PDUの
 *                 pdu_typeと同じ)
 *   opcode      = WQE投稿時: 実際に書き込んだopcode(MLX5_OPCODE_*)。
 *                 CQE消費時: CQEのopcode(REQ/RESP_SEND/REQ_ERR/RESP_ERR等)
 *   hlen        = ds_cnt(SQ投稿のみ有効、WQEのdata segment数)
 *   status      = syndrome(CQE_ERRのみ有効、下位8bit使用)
 *   pdu_len     = qpn(このQPのqueue pair番号、常に有効)
 *   ttag        = counter(このイベント時点のsq_pc[SQ投稿後]/rq_pc[RQ投稿後]/
 *                 cq_cc[CQE消費後]の値 -- どのWQE/CQEスロットかを追跡する)
 *   data_length = len(WQE: byte_count) / byte_cnt(CQE: RESP_SENDのみ有効)
 *   data_offset = remote_addr下位32bit(RDMA_WRITE/READのみ有効)
 *   cid/cccid   = remote_rkey上位16bit/下位16bit(RDMA_WRITE/READのみ有効、
 *                 2つ合わせて32bitのrkeyを表す) */
typedef struct {
    uint64_t ticks;         /*  0: timer_now()の値 */
    uint32_t tag;            /*  8: File#|Func#|info(TS_MK()で組み立てる) */
    uint32_t arg;             /* 12: 呼び出し側が決める補助値(plain ts_log()用、
                                *     拡張系記録関数では常に0) */

    uint8_t  kind;            /* 16: TS_KIND_* */
    uint8_t  pdu_type;        /* 17: CH: NVMe/TCP PDU種別(nvme_tcp_pdu.hのNVME_TCP_PDU_*)
                                *     / RDMA: TS_RDMA_OP_* */
    uint8_t  hlen;             /* 18: CH: PDUヘッダ長(nvme_tcp_hdr_t.hlen) / RDMA: ds_cnt */
    uint8_t  pdo;              /* 19: CH: PDU Data Offset(nvme_tcp_hdr_t.pdo) */
    uint16_t cid;             /* 20: PSH: Command ID(CapsuleCmd/RSP) / RDMA: rkey上位16bit */
    uint16_t cccid;           /* 22: PSH: このデータ/R2Tが属するコマンドのCID(R2T/H2C/C2HData)
                                *     / RDMA: rkey下位16bit */
    uint16_t status;          /* 24: PSH: NVMeステータス(RSPのみ) / RDMA: syndrome */
    uint16_t tcp_flags;       /* 26: TCPフラグビット */
    uint32_t pdu_len;         /* 28: CH: PDU全体長(plen) / RDMA: qpn */
    uint32_t data_offset;     /* 32: PSH: DATAO(H2C/C2HData) / R2TO(R2T)
                                *     / RDMA: remote_addr下位32bit */
    uint32_t data_length;     /* 36: PSH: DATAL(H2C/C2HData) / R2TL(R2T) / LEN(CapsuleCmd、
                                *     SGLディスクリプタが宣言する転送量) / RDMA: len/byte_cnt */
    uint32_t ttag;            /* 40: PSH: Transfer Tag(R2T/H2CData) / RDMA: sq_pc/rq_pc/cq_cc */
    uint32_t tcp_seq;         /* 44: TCP seq */
    uint32_t tcp_ack_seq;     /* 48: TCP ack_seq */
    uint32_t tcp_window;      /* 52: 実効ウィンドウサイズ(スケーリング適用後) */

    uint8_t  conn_slot;       /* 56: 接続スロット番号(tcp.cのtcp_conn_slot()と同じ意味、
                                *     TS_KIND_TCP_ACK以外は常に0) -- NVMe/TCPはadmin/IO
                                *     queueが別々のTCPコネクションとして同時に生きるため、
                                *     タグだけでは区別できない(tcp.cのts_conn_arg()コメント
                                *     と同じ理由) */
    uint8_t  opcode;          /* 57: PSH: NVMeコマンドopcode(CapsuleCmdのみ意味を持つ)
                                *     / RDMA: WQE投稿opcode / CQE opcode */
    uint8_t  sgl_type;        /* 58: PSH: SGLディスクリプタtype(CapsuleCmdのみ、
                                *     nvme_types.hのNVME_SGL_TYPE_*) */
    uint8_t  pad[5];          /* 59: 予約(将来拡張用、常に0) */
} ts_entry_t;                 /* 64 bytes */

/* ts_log_nvme_tcp_pdu()呼び出し用の引数構造体(呼び出し側のスタックに
 * 一時的に置くだけの用途なので、ts_entry_tと違いサイズ・レイアウトに
 * 制約は無い)。CH(pdu_type/hlen/pdo/plen)は全PDU種別で必ず埋めること。
 * PSHはpdu_typeに応じて次の組み合わせだけ埋めればよい(それ以外は0の
 * ままでよい、ts_log_dump_core()がpdu_typeを見て表示するフィールドを
 * 選ぶ):
 *   CapsuleCmd(NVME_TCP_PDU_CMD):    cid, opcode, sgl_type, data_length(=LEN)
 *   RSP(NVME_TCP_PDU_RSP):           cid, status
 *   R2T(NVME_TCP_PDU_R2T):           cccid, ttag, data_offset(=R2TO), data_length(=R2TL)
 *   H2CData/C2HData:                 cccid, ttag, data_offset(=DATAO), data_length(=DATAL)
 *     (pdoは上のCHで表示されるが、H2CData/C2HDataでは実データの開始位置
 *      として特に意味を持つため呼び出し側は必ず設定すること) */
typedef struct {
    /* CH: 全PDU種別共通(nvme_tcp_pdu.hのnvme_tcp_hdr_t参照) */
    uint8_t  pdu_type;
    uint8_t  hlen;
    uint8_t  pdo;
    uint32_t plen;

    /* PSH: pdu_typeに応じて有効な組み合わせが変わる(上記コメント参照) */
    uint16_t cid;
    uint8_t  opcode;
    uint8_t  sgl_type;
    uint16_t status;
    uint16_t cccid;
    uint32_t ttag;
    uint32_t data_offset;
    uint32_t data_length;
} ts_nvme_pdu_t;

/* RDMA sub-event種別(2026-08-12追加、ts_log_rdma()/ts_rdma_t参照)。
 * ts_entry_t.pdu_typeへそのまま渡す(NVMe/TCP PDUのpdu_typeと同じ
 * 「switchで表示形式を選ぶ」役割) -- ConnectXへのSQ/RQ WQE投稿
 * (「設定内容」)とConnectXからのCQE消費(「受信内容」)を同じkindの
 * 中で種別分けする。 */
#define TS_RDMA_OP_SQ_SEND        1u  /* mlx5_qp_post_send()/post_send_ud() */
#define TS_RDMA_OP_SQ_RDMA_WRITE  2u  /* mlx5_qp_post_rdma_write() */
#define TS_RDMA_OP_SQ_RDMA_READ   3u  /* mlx5_qp_post_rdma_read() */
#define TS_RDMA_OP_RQ_POST        4u  /* mlx5_qp_post_recv()/post_recv_gsi() */
#define TS_RDMA_OP_CQE            5u  /* poll_cqe()系が成功CQEを消費(rc==1) */
#define TS_RDMA_OP_CQE_ERR        6u  /* poll_cqe()系がエラー系CQEを消費(rc==-1) */
#define TS_RDMA_OP_CMD_RECV       7u  /* 2026-08-12追加: nvmet_rdma.cがRQ完了から
                                        * 新規NVMeコマンド(SQE)を実際にparseした
                                        * 瞬間(ユーザー指示 -- 「NVMeコマンドを
                                        * 受信したときのtimestampも追加してほしい」、
                                        * SQ_RDMA_READ/CQEとの時系列比較で「同時に
                                        * 何コマンド受信済みか」を直接確認できる
                                        * ようにする) */

/* ts_log_rdma()呼び出し用の引数構造体(ts_nvme_pdu_tと同じ位置づけ、
 * 呼び出し側のスタック上の一時変数でよい)。rdma_opに応じて次の組み合わせ
 * だけ埋めればよい(それ以外は0のままでよい、ts_log_dump_core()がrdma_op
 * を見て表示するフィールドを選ぶ):
 *   SQ_SEND:                 qpn, wqe_opcode, ds_cnt, len, counter(=投稿後のsq_pc)
 *   SQ_RDMA_WRITE/READ:      上記に加えremote_addr, remote_rkey
 *   RQ_POST:                 qpn, len, counter(=投稿後のrq_pc)
 *   CQE:                     qpn, cqe_opcode, len(=byte_cnt、RESP_SENDのみ
 *                            意味を持つ、他は0), counter(=消費後のcq_cc)
 *   CQE_ERR:                 qpn, cqe_opcode, syndrome, counter(=消費後のcq_cc)
 *   CMD_RECV:                qpn, wqe_opcode(=NVMeコマンドopcode、nvme_types.hの
 *                            NVME_IO_CMD_系またはNVME_FABRIC_CMD)、
 *                            remote_addr(=cid、フィールド流用)、
 *                            len(=要求転送量、ksgl_len)、
 *                            counter(=parse時点のrq_pc、どのRQスロット由来かを
 *                            示す) */
typedef struct {
    uint8_t  rdma_op;       /* TS_RDMA_OP_* */
    uint8_t  wqe_cqe_opcode; /* WQE投稿opcode(MLX5_OPCODE_*)またはCQE opcode
                               * / CMD_RECV: NVMeコマンドopcode */
    uint8_t  ds_cnt;         /* SQ投稿のみ有効(WQEのdata segment数) */
    uint8_t  syndrome;       /* CQE_ERRのみ有効 */
    uint32_t qpn;
    uint32_t counter;        /* このイベント時点のsq_pc/rq_pc/cq_cc */
    uint32_t len;            /* WQE: byte_count / CQE: byte_cnt(RESP_SENDのみ)
                               * / CMD_RECV: 要求転送量(ksgl_len) */
    uint32_t remote_addr;    /* RDMA_WRITE/READのみ有効(下位32bit)
                               * / CMD_RECV: NVMeコマンドのcid(フィールド流用) */
    uint32_t remote_rkey;    /* RDMA_WRITE/READのみ有効 */
} ts_rdma_t;

/* ================================================================
 * tag の新形式(2026-08-14、ユーザー指示で全面見直し):
 *   bit[31:24] = File#  (呼び出し元ファイル、TS_FILE_* enum)
 *   bit[23:16] = Func#  (呼び出し元関数、TS_FUNC_* enum、グローバル一意)
 *   bit[15:00] = info   (同一関数内で複数回呼ぶ場合の通し番号、0始まり)
 * 第2引数 arg(32bit の補助値)は従来通り「その呼び出しが記録したい実値」
 * (バイト数・conn_slot・PSN 等)を入れる -- info とは別。
 *
 * TS_MK() でタグを組み立て、ts コマンドが File名:Func名#info を表示する。
 * 絞り込みは `ts mask <mask> <value>`((tag & mask)==value)で行う
 * (旧 `ts type <4文字タグ>` は廃止)。Func# はファイルごとに上位ニブルを
 * 揃えて割り当ててあるので(tcp=0x0X, nvme=0x1X, mlx5_net=0x2X, nvmet=0x3X,
 * nvmet_tcp=0x4X, mlx5_qp=0x5X, eth=0x6X, nvme_tcp=0x7X, nvmet_rdma=0x8X)、
 * 例: `ts mask 0x00f00000 0x00200000` で mlx5_net.c の全関数を抽出できる。 */
#define TS_MK(file, func, info) \
    ( ((uint32_t)(uint8_t)(file) << 24) \
    | ((uint32_t)(uint8_t)(func) << 16) \
    | ((uint32_t)(uint16_t)(info)) )

#define TS_TAG_FILE(tag) ((uint8_t)((uint32_t)(tag) >> 24))
#define TS_TAG_FUNC(tag) ((uint8_t)((uint32_t)(tag) >> 16))
#define TS_TAG_INFO(tag) ((uint16_t)(uint32_t)(tag))

/* File# 定義。値は tag bit[31:24] にそのまま入る。追加時は timestamp.c の
 * ts_file_name() にも名前を追記すること。 */
enum ts_file {
    TS_FILE_TCP        = 0x01u,
    TS_FILE_NVME       = 0x02u,
    TS_FILE_MLX5_NET   = 0x03u,
    TS_FILE_NVMET      = 0x04u,
    TS_FILE_NVMET_TCP  = 0x05u,
    TS_FILE_MLX5_QP    = 0x06u,
    TS_FILE_ETH        = 0x07u,
    TS_FILE_NVME_TCP   = 0x08u,
    TS_FILE_NVMET_RDMA = 0x09u,
};

/* Func# 定義(グローバル一意、上位ニブルでファイルを緩くグループ化)。
 * 追加時は timestamp.c の ts_func_name() にも名前を追記すること。 */
enum ts_func {
    /* tcp.c (0x0X) */
    TS_FUNC_tcp_send_segment      = 0x01u,
    TS_FUNC_tcp_send              = 0x02u,
    TS_FUNC_tcp_recv_internal     = 0x03u,
    TS_FUNC_tcp_input             = 0x04u,
    TS_FUNC_tcp_async_poll        = 0x05u,
    TS_FUNC_tcp_async_short_poll  = 0x06u,
    TS_FUNC_tcp_send_async_enqueue= 0x07u,
    TS_FUNC_tcp_send_async_short  = 0x08u,
    /* nvme.c (0x1X) */
    TS_FUNC_nvme_read_pipelined_run   = 0x10u,
    TS_FUNC_nvme_write_pipelined_run  = 0x11u,
    TS_FUNC_nvme_pipeline_read_rx_tick= 0x12u,
    TS_FUNC_nvme_pipeline_rx_tick     = 0x13u,
    TS_FUNC_nvme_pipeline_h2c_pump    = 0x14u,
    TS_FUNC_nvme_connect_job_step     = 0x15u,
    TS_FUNC_nvme_exec_step            = 0x16u,
    /* mlx5_net.c (0x2X) */
    TS_FUNC_mlx5_net_post_frame       = 0x20u,
    TS_FUNC_mlx5_net_post_lso_frame   = 0x21u,
    TS_FUNC_mlx5_net_sq_wait_room     = 0x22u,
    TS_FUNC_mlx5_net_try_recover      = 0x23u,
    TS_FUNC_mlx5_wqe_analyze          = 0x24u,
    TS_FUNC_mlx5_net_send_frags       = 0x25u,
    TS_FUNC_mlx5_net_send_frags_async = 0x26u,
    TS_FUNC_mlx5_net_send_lso_async   = 0x27u,
    TS_FUNC_mlx5_net_sq_reap_one      = 0x28u,
    TS_FUNC_mlx5_net_poll_recv        = 0x29u,
    /* nvmet.c (0x3X) */
    TS_FUNC_nvmet_admin_dispatch      = 0x30u,
    TS_FUNC_nvmet_io_dispatch_cmd     = 0x31u,
    TS_FUNC_nvmet_io_dispatch_h2c     = 0x32u,
    TS_FUNC_nvmet_io_job_step_impl    = 0x33u,
    TS_FUNC_nvmet_admin_job_step      = 0x34u,
    TS_FUNC_nvmet_io_rx_upcall        = 0x35u,
    /* nvmet_tcp.c (0x4X) */
    TS_FUNC_nvmet_tcp_recv_cmd        = 0x40u,
    TS_FUNC_nvmet_tcp_recv_cmd_body   = 0x41u,
    TS_FUNC_nvmet_tcp_send_c2h        = 0x42u,
    TS_FUNC_nvmet_tcp_send_c2h_async  = 0x43u,
    TS_FUNC_nvmet_tcp_send_icresp     = 0x44u,
    TS_FUNC_nvmet_tcp_send_r2t        = 0x45u,
    TS_FUNC_nvmet_tcp_send_resp       = 0x46u,
    /* mlx5_qp.c (0x5X) */
    TS_FUNC_mlx5_qp_post_send         = 0x50u,
    TS_FUNC_mlx5_qp_post_send_ud      = 0x51u,
    TS_FUNC_mlx5_qp_post_rdma_common  = 0x52u,
    TS_FUNC_mlx5_qp_post_recv         = 0x53u,
    TS_FUNC_mlx5_qp_post_recv_gsi     = 0x54u,
    TS_FUNC_mlx5_qp_poll_cqe          = 0x55u,
    TS_FUNC_mlx5_qp_poll_cqe_gsi      = 0x56u,
    /* eth.c (0x6X) */
    TS_FUNC_eth_dump_tx_ring_debug    = 0x60u,
    TS_FUNC_eth_tx_queue              = 0x61u,
    /* nvme_tcp.c (0x7X) */
    TS_FUNC_nvme_tcp_recv_poll        = 0x70u,
    /* nvmet_rdma.c (0x8X) */
    TS_FUNC_nvmet_rdma_job_step       = 0x80u,
};

/* 現在時刻(timer_now())をtag/argと共に1件記録する(kind=TS_KIND_PLAIN、
 * 拡張フィールドは全て0クリア)。バッファが満杯になったら最も古い
 * エントリから上書きする(リングバッファ)。 */
void ts_log(uint32_t tag, uint32_t arg);

/* NVMe/TCP PDUイベントを1件記録する(kind=TS_KIND_NVME_PDU)。
 * tag:  TS_MK(TS_FILE_*, TS_FUNC_*, info)。File名:Func名#info で表示される。
 * info: CH(全種別共通)+PSH(pdu_typeに応じた組み合わせ)、ts_nvme_pdu_tの
 *       ドキュメント参照。呼び出し元のスタック上の一時変数を指せばよい
 *       (この関数はすぐに中身をコピーする、infoの寿命は呼び出し中だけで
 *       よい)。
 *
 * 引数はconst volatile ts_nvme_pdu_t*であること(constだけではない点に
 * 注意)。呼び出し元がinfoを`ts_nvme_pdu_t info = {0}; info.a = x; info.b = y;`
 * のように個々のフィールドへ逐次代入して組み立てる場合、infoが非volatile
 * だとGCC -O2が隣接する狭いフィールドへの代入(例: 1バイトのhlenと
 * それに続く1バイトのpdo)を1回のワイドストアへ結合することがあり、
 * その結合先アドレスがinfo構造体内で自然境界に乗らない(例: offset1から
 * の2バイトストア)場合に実機でAlignment faultを起こす(2026-08-11、
 * 実機で確認済みの本物のバグ -- timestamp.c/CLAUDE.md「ローカル
 * スクラッチバッファへの逐次1バイト代入もvolatileが必須」節と同じ
 * クラス、ts_entry_t自体の書き込み[ts_entry_clear_ext()]は元々volatile
 * 経由だったが、呼び出し側が新設ts_nvme_pdu_tを組み立てる際にこの
 * 規約の適用を失念していた)。呼び出し元は`volatile ts_nvme_pdu_t info
 * = {0};`で宣言しフィールドを個別代入すること -- volatile宣言により
 * 各代入が個別のアクセスとして保証され、結合による誤ったアライメントの
 * ワイドストアが生成されなくなる。`&info`はvolatile→const volatileへの
 * 修飾追加のみのため暗黙変換でき、呼び出し側でキャストは不要。 */
void ts_log_nvme_tcp_pdu(uint32_t tag, const volatile ts_nvme_pdu_t *info);

/* ConnectX SQ/RQ WQE投稿・CQE消費イベントを1件記録する(kind=TS_KIND_RDMA、
 * 2026-08-12追加、ユーザー指示 -- 「ts_log_nvme_tcp_pduのRDMA版」)。
 * tag:  TS_MK(TS_FILE_*, TS_FUNC_*, info)。呼び出し元関数ごとにFunc#が
 *       変わる(mlx5_qp.cのpost_send/post_recv/post_rdma_common/poll_cqe系、
 *       nvmet_rdma.cのnvmet_rdma_job_step)。どのQP(qpn)で何が起きたか
 *       (rdma_op)はinfo側の拡張フィールドで表現する。`ts mask 0xff000000
 *       0x06000000`でmlx5_qp.c全体を横断的に見られる。
 * info: ts_rdma_tのドキュメント参照。呼び出し元のスタック上の一時変数を
 *       指せばよい(この関数はすぐに中身をコピーする)。
 *
 * 引数はconst volatile ts_rdma_t*であること -- ts_log_nvme_tcp_pdu()と
 * 同じ理由(隣接する狭いフィールドへの逐次代入がコンパイラに結合され
 * 実機でAlignment faultを起こす、CLAUDE.md「ローカルスクラッチバッファへの
 * 逐次1バイト代入もvolatileが必須」節参照)。呼び出し元は
 * `volatile ts_rdma_t info = {0};`で宣言しフィールドを個別代入すること。 */
void ts_log_rdma(uint32_t tag, const volatile ts_rdma_t *info);

/* TCP ACK / Window Updateイベントを1件記録する(kind=TS_KIND_TCP_ACK)。
 * tag:       TS_MK(TS_FILE_*, TS_FUNC_*, info)。
 * conn_slot: 接続スロット番号(tcp.cのtcp_conn_slot()と同じ値。呼び出し元が
 *            単一コネクションしか扱わない場合は0を渡せばよい)。
 * seq/ack_seq: TCP seq / ack_seq。
 * window: 実効ウィンドウサイズ(スケーリング適用済みの値)。
 * flags:  TCPフラグビット(ACK/PSH/RST等)。 */
void ts_log_tcp_ack(uint32_t tag, uint8_t conn_slot, uint32_t seq,
                     uint32_t ack_seq, uint32_t window, uint16_t flags);

/* ================================================================
 * 表示系API(2026-08-08、ユーザー指示で統一): モードごとに別々の表示
 * 関数を持つのをやめ、「(必要なら)開始通し番号をquery関数で問い合わせる
 * →唯一の表示関数ts_log_dump_core()を(core, start, count, tag)で呼ぶ」
 * という2段構成に統一した。command.cの`ts`コマンドはオプションを解析
 * した後、必ずこの2段階を踏む(以前はモードごとに走査・表示ロジックが
 * 個別の関数に重複していた)。
 *
 * coreは常に0またはSMP_MAX_CORES-1未満を明示指定する -- `ts`コマンド
 * 自体は常にcore0のシェルからdispatch()されるため、core1にpin止めした
 * ジョブ(nvmet-io等)の記録を見るには明示指定が必要(2026-08-08、
 * マルチコア化Phase 6で追加)。coreがSMP_MAX_CORES以上ならcore0として
 * 扱う(以下の全関数共通)。
 * ================================================================ */

/* 直近count件を表示するための開始通し番号を返す
 * (ts_log_dump_core()のstart引数にそのまま渡せる)。 */
uint64_t ts_log_query_start_last_n(unsigned core, uint32_t count);

/* (tag & mask)==value に一致するエントリのうち直近count件を表示するための
 * 開始通し番号を返す -- ts_log_dump_core()を呼ぶ際は同じmask/valueを渡す
 * こと(一致以外をスキップしながら数える必要があるため、開始番号だけでは
 * 表現できない)。一致がcount件に満たない場合は保持範囲の先頭を返す。 */
uint64_t ts_log_query_start_last_n_matching(unsigned core, uint32_t mask, uint32_t value, uint32_t count);

/* coreのリングバッファのstart(通し番号 -- 上記query関数群の戻り値、
 * または`ts start <N> end <N>`のように呼び出し側が直接指定した値)から、
 * tagが0なら無条件に、0以外ならtag一致するものだけを、最大count件表示
 * する。startが現在保持している範囲の外にあっても自動的にクランプする。
 * 各行: 通し番号、絶対tick(16桁hex)、直前に表示した(tag指定時は
 * 「直前に一致した」)エントリからのdelta(us)、tag(hexおよびASCII
 * 可能ならその文字列)、arg(hex)。kindがTS_KIND_NVME_PDU/TS_KIND_TCP_ACK
 * のエントリは、続けて対応するPDU/TCP詳細を同じ行の末尾に追記する
 * (改行はしない)。 */
void ts_log_dump_core(unsigned core, uint64_t start, uint32_t count, uint32_t mask, uint32_t value);

/* フリーズ機能(2026-07-25追加)。実機で「TXリング枠待ちタイムアウト」の
 * 後始末(eth_tx_recover()、TCP再送、Ctrl+C中断、セッション終了/FIN再送等)
 * が大量にts_log()を発生させ、肝心の障害直前の文脈(TXQE/SSEG等)が
 * リングバッファから完全に押し出されて`ts type TXRD`が「タグ一致なし」を
 * 返す事象を確認した -- ネットワーク越しにハングを見てから`ts`コマンドを
 * 打つまでの間にシェルがnvmetでブロックされ続けるため、ユーザ側で
 * 「即座に読む」対策が取れないのが根本問題。
 *
 * ts_log_freeze()は呼び出し時点の直近TS_FREEZE_COUNT件を、以後の
 * ts_log()呼び出しでは一切上書きされない別バッファへコピーする --
 * 障害検出直後、後始末処理が走るより前に呼べば、その時点までの文脈を
 * 恒久的に保存できる(次にts_log_freeze()が呼ばれるまで有効)。 */
#define TS_FREEZE_COUNT 2048u

void ts_log_freeze(void);

/* ts_log_set_paused()/ts_log_is_paused()の明示的コア指定版
 * (ts_log_dump_core()と同じ理由 -- 常にcore0で動くコード
 * (temp_test()等)から、core1にpin止めしたジョブの記録も一緒に
 * 一時停止/再開するため)。coreがSMP_MAX_CORES以上ならcore0として扱う。 */
void ts_log_set_paused_core(unsigned core, int paused);

uint32_t ts_log_mode(void);
void  ts_log_mode_set(uint32_t mode);

/* ts_log_mode のビット割り当て(呼び出し側が & で自分のビットを見る):
 *   bit0(0x1): コマンドレベル/低頻度診断(tcp_send・tcp_recv・tcp_async・
 *              nvmet/nvme/rdma のPDUログ等、概ね1コマンドに数回)。既定ON。
 *   bit1(0x2): nvmet.cのpush受信 per-CMD診断。既定OFF。
 *   bit2(0x4): per-frame/per-segment のRX/TXステージ計装(mlx5_net poll_recv の
 *              MRXF/MRXI/../、tcp_send_segment の SSLT/SCKS/../、tcp_input の
 *              per-segment ログ)。256KBあたり ~28セグメント×各数回走るため
 *              受信ホットパスに実測 ~20% のオーバーヘッドを乗せる。**既定OFF**。
 *              計測時のみ `ts mode 5`(bit0+bit2)等で有効化する。
 * per-frame/per-segment の ts_log は下記 TS_HOT() でゲートすること。 */
#define TS_MODE_HOTPATH 0x4u
#define TS_HOT(tag, arg) do { if (ts_log_mode() & TS_MODE_HOTPATH) ts_log((tag), (arg)); } while (0)
#endif /* TIMESTAMP_H */
