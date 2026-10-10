#ifndef MLX5_QP_DATAPATH_H
#define MLX5_QP_DATAPATH_H

#include "mlx5.h"
#include "timestamp.h"

int mlx5_qp_post_send(mlx5_dev_t *dev, mlx5_qp_t *qp, const void *data, uint32_t len);
/* SEND を 2 バッファ(コマンド capsule + データ)から 1 メッセージとして送る。
 * data1=NULL なら上と同じ。NVMe-oF の in-capsule write 用。 */
int mlx5_qp_post_send2(mlx5_dev_t *dev, mlx5_qp_t *qp, const void *data0, uint32_t len0,
                       const void *data1, uint32_t len1);
/* inval_rkey が非 0 なら SEND_WITH_INVALIDATE で送り、相手の HCA に
 * その rkey を無効化させる(ホスト側の LOCAL_INV が要らなくなる)。 */
int mlx5_qp_post_send_ex(mlx5_dev_t *dev, mlx5_qp_t *qp, const void *data0, uint32_t len0,
                         const void *data1, uint32_t len1, uint32_t inval_rkey);

int mlx5_qp_post_recv(mlx5_dev_t *dev, mlx5_qp_t *qp, void *buf, uint32_t buf_len);

int mlx5_qp_post_rdma_write(mlx5_dev_t *dev, mlx5_qp_t *qp, const void *local_data, uint32_t len,
                             uint64_t remote_addr, uint32_t remote_rkey);
int mlx5_qp_post_rdma_read(mlx5_dev_t *dev, mlx5_qp_t *qp, void *local_buf, uint32_t len,
                            uint64_t remote_addr, uint32_t remote_rkey);

int mlx5_qp_poll_cqe(mlx5_dev_t *dev, mlx5_qp_t *qp, int *out_is_send,
                     uint32_t *out_recv_len, uint8_t *out_syndrome);

uint8_t mlx5_qp_last_cqe_opcode(mlx5_dev_t *dev, mlx5_qp_t *qp);

int mlx5_qp_post_send_ud(mlx5_dev_t *dev, mlx5_qp_t *qp, const void *data, uint32_t len,
                          uint32_t remote_qpn, uint32_t remote_qkey,
                          const uint8_t remote_gid[16], const uint8_t remote_mac[6]);

/* 受信先は GSI のリング(buf は使わない)。届いたデータは mlx5_qp_gsi_last_rx() で読む。 */
int mlx5_qp_post_recv_gsi(mlx5_dev_t *dev, mlx5_qp_t *qp, void *buf, uint32_t buf_len);

int mlx5_qp_poll_cqe_gsi(mlx5_dev_t *dev, mlx5_qp_t *qp, int *out_is_send,
                          uint32_t *out_recv_len, uint8_t *out_syndrome);

/* 直前に mlx5_qp_poll_cqe_gsi() が拾った受信完了のデータ(GRH 40 バイトから)。 */
const volatile uint8_t *mlx5_qp_gsi_last_rx(mlx5_dev_t *dev);

#endif /* MLX5_QP_DATAPATH_H */
