#ifndef MLX5_QP_DATAPATH_H
#define MLX5_QP_DATAPATH_H

#include "mlx5.h"
#include "timestamp.h"

// 2026-08-14 tagの新形式(File#|Func#|info、timestamp.h参照)への全面移行に
// 伴い、旧TS_TAG_MLX5_QP(共通4文字タグ'RDMA')は廃止した。mlx5_qp.c/
// nvmet_rdma.cの各ts_log_rdma()呼び出しは、それぞれの呼び出し元関数の
// TS_MK(TS_FILE_*, TS_FUNC_*, info)を直接使う。

// RC QP経由でSEND WQEを1個投稿する(ctrl_seg+data_seg、ds_cnt=2、
// リモートQPのRECV WQEへ配送される)。dataはqp->mkey(rw/rr有効)で
// 参照可能な任意のローカルバッファ。成功時0、失敗時負値。
int mlx5_qp_post_send(mlx5_dev_t *dev, mlx5_qp_t *qp, const void *data, uint32_t len);

// RC QPのRQへRECV WQEを1個投稿する(data_segのみ、ds_cnt=1)。相手からの
// SENDを受け取るバッファを指定する。成功時0、失敗時負値。
int mlx5_qp_post_recv(mlx5_dev_t *dev, mlx5_qp_t *qp, void *buf, uint32_t buf_len);

// フェーズ(c): RDMA_WRITE/RDMA_READ。remote_addr/remote_rkeyは相手QPの
// mkey(rw/rr有効、mlx5_qp_t.mkey)とその物理アドレス空間内のオフセット
// (mlx5_dma_addr()と同じ規約)。CQEは常に送信元(呼び出した側のQP)にのみ
// 生成される(相手側には通知されない、IBTA仕様通り)。成功時0、失敗時負値。
int mlx5_qp_post_rdma_write(mlx5_dev_t *dev, mlx5_qp_t *qp, const void *local_data, uint32_t len,
                             uint64_t remote_addr, uint32_t remote_rkey);
int mlx5_qp_post_rdma_read(mlx5_dev_t *dev, mlx5_qp_t *qp, void *local_buf, uint32_t len,
                            uint64_t remote_addr, uint32_t remote_rkey);

// QPの共有CQを1件だけ非ブロッキングでポーリングする(owner-bitトグル
// 判定、mlx5_net.cのmlx5_net_cqe_if_ready()と同じロジック)。
// 戻り値: 1=CQE取得、0=無し、-1=エラー系CQE(syndromeをout_syndromeへ)。
// out_is_send: 1なら送信完了(SQ側)、0なら受信到着(RQ側、byte_cntを
// out_recv_lenへ)。
int mlx5_qp_poll_cqe(mlx5_dev_t *dev, mlx5_qp_t *qp, int *out_is_send,
                     uint32_t *out_recv_len, uint8_t *out_syndrome);

// 診断用(2026-08-12): 直前のmlx5_qp_poll_cqe()呼び出しが消費したCQEの
// opcode(上位nibble)を読む。REQ_ERR(0xd)=自分がrequester側だった操作の
// エラー、RESP_ERR(0xe)=自分がresponder側だった操作のエラー、を区別する。
uint8_t mlx5_qp_last_cqe_opcode(mlx5_dev_t *dev, mlx5_qp_t *qp);

// PF0<->PF1(既にbring-up済みの2つのmlx5_dev_t)でRC QPを1本ずつ作成し、
// 相互にQPN/PSN/GID/MACを設定してRTSへ遷移させ、双方向のSEND/RECVを
// 1発ずつ試す一発診断。`mlx5qp pingpong`シェルコマンド用。
void mlx5_qp_pingpong_test(mlx5_dev_t *dev0, mlx5_dev_t *dev1);

// フェーズ(c): PF0<->PF1でRC QPを確立し、双方向のRDMA_WRITE/RDMA_READと
// 異常系(誤ったrkey)を確認する。`mlx5qp rdma`シェルコマンド用。
void mlx5_qp_rdma_test(mlx5_dev_t *dev0, mlx5_dev_t *dev1);

// 2026-08-11、フェーズ(b)実機診断: 同一PF(同一devfn、同一command
// interface)内に2本のRC QPを作り、互いに自分自身のGID/MACを使って接続
// する(クロスPF/vport分離が本当にINIT2RTR_QPのBAD_OP_ERRの原因かを
// 切り分けるための対照実験)。`mlx5qp loop <0|1>`シェルコマンド用。
void mlx5_qp_loopback_test(mlx5_dev_t *dev, const char *label);

// フェーズ(d): UD/GSI QP経由でSEND WQEを1個投稿する(ctrl_seg+
// datagram_seg[Address Vector, 48B=3DS]+data_seg、ds_cnt=5、2WQEBB消費
// -- mlx5_net.cの「偶数アライン方式」[2フラグメントゼロコピー送信、
// 全く同じds_cnt=5サイズで既に実機実績あり]と構造的に同一)。相手の
// qkey/QPN/GID/MACは呼び出しごとに指定する(UDは接続を持たず、送信WQE
// 自体に宛先アドレスを埋め込むため)。
int mlx5_qp_post_send_ud(mlx5_dev_t *dev, mlx5_qp_t *qp, const void *data, uint32_t len,
                          uint32_t remote_qpn, uint32_t remote_qkey,
                          const uint8_t remote_gid[16], const uint8_t remote_mac[6]);

// フェーズ(d): GSI/UD QPのRQへRECV WQEを1個投稿する(RC専用の
// mlx5_qp_post_recv()と同じフォーマット、GSI専用のDMA領域を参照する
// 点だけが異なる)。mlx5.hのMLX5_GRH_BYTES参照。
int mlx5_qp_post_recv_gsi(mlx5_dev_t *dev, mlx5_qp_t *qp, void *buf, uint32_t buf_len);

// フェーズ(d): GSI/UD QPの共有CQを1件だけ非ブロッキングでポーリングする
// (RC専用のmlx5_qp_poll_cqe()と同じロジック、GSI専用のCQアドレスを
// 参照する点だけが異なる)。戻り値/引数の意味はmlx5_qp_poll_cqe()と同一。
int mlx5_qp_poll_cqe_gsi(mlx5_dev_t *dev, mlx5_qp_t *qp, int *out_is_send,
                          uint32_t *out_recv_len, uint8_t *out_syndrome);

// フェーズ(d): PF0<->PF1でUD(またはGSI/QP1相当、use_gsiで選択)QPを1本
// ずつ作り、RTSまで遷移させ、PF0からPF1へダミーのMAD形式パケットを1個
// 送信・到着・内容一致を確認する一発診断。`mlx5mad test`シェルコマンド用。
void mlx5_gsi_mad_test(mlx5_dev_t *dev0, mlx5_dev_t *dev1, int use_gsi);

#endif /* MLX5_QP_DATAPATH_H */
