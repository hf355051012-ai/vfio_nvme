#ifndef MLX5_QP_DATAPATH_H
#define MLX5_QP_DATAPATH_H

#include "mlx5.h"
#include "timestamp.h"

int mlx5_qp_post_send(mlx5_dev_t *dev, mlx5_qp_t *qp, const void *data, uint32_t len);
/* SEND を 2 バッファ(コマンド capsule + データ)から 1 メッセージとして送る。
 * data1=NULL なら上と同じ。NVMe-oF の in-capsule write 用。 */
int mlx5_qp_post_send2(mlx5_dev_t *dev, mlx5_qp_t *qp, const void *data0, uint32_t len0,
                       const void *data1, uint32_t len1);

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

int mlx5_qp_post_recv_gsi(mlx5_dev_t *dev, mlx5_qp_t *qp, void *buf, uint32_t buf_len);

int mlx5_qp_poll_cqe_gsi(mlx5_dev_t *dev, mlx5_qp_t *qp, int *out_is_send,
                          uint32_t *out_recv_len, uint8_t *out_syndrome);

#endif /* MLX5_QP_DATAPATH_H */
