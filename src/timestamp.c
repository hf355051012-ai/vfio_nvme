#include "timestamp.h"
#include "timer.h"
#include "uart.h"
#include "nvme_tcp_pdu.h"  // NVME_TCP_PDU_* -- pdu_typeの文字列化にのみ使う
#include "smp.h"

static ts_entry_t s_ts_buf[SMP_MAX_CORES][TS_LOG_COUNT] __attribute__((aligned(64)));
static uint64_t   s_ts_total[SMP_MAX_CORES];  // 単調増加、ts_log*()の累計呼び出し回数
static volatile int s_ts_paused[SMP_MAX_CORES];  // 1の間はts_log*()系が即座に何もせず返る

_Static_assert(sizeof(ts_entry_t) == TS_LOG_ENTRY_BYTES,
               "ts_entry_t must be exactly 64 bytes");

static void ts_entry_clear_ext(volatile ts_entry_t *e)
{
    e->kind        = TS_KIND_PLAIN;
    e->pdu_type    = 0;
    e->hlen        = 0;
    e->pdo         = 0;
    e->cid         = 0;
    e->cccid       = 0;
    e->status      = 0;
    e->tcp_flags   = 0;
    e->pdu_len     = 0;
    e->data_offset = 0;
    e->data_length = 0;
    e->ttag        = 0;
    e->tcp_seq     = 0;
    e->tcp_ack_seq = 0;
    e->tcp_window  = 0;
    e->conn_slot   = 0;
    e->opcode      = 0;
    e->sgl_type    = 0;
    for (int i = 0; i < 5; i++) {
        e->pad[i] = 0;
    }
}

void ts_log(uint32_t tag, uint32_t arg)
{
    unsigned core = smp_core_index();
    if (s_ts_paused[core]) return;
    uint32_t   idx = (uint32_t)(s_ts_total[core] & (TS_LOG_COUNT - 1));
    volatile ts_entry_t *e = &s_ts_buf[core][idx];

    e->ticks = timer_now();
    e->tag   = tag;
    e->arg   = arg;
    ts_entry_clear_ext(e);  // kind=TS_KIND_PLAINのまま

    s_ts_total[core]++;
}

void ts_log_nvme_tcp_pdu(uint32_t tag, const volatile ts_nvme_pdu_t *info)
{
    unsigned core = smp_core_index();
    if (s_ts_paused[core]) return;
    uint32_t   idx = (uint32_t)(s_ts_total[core] & (TS_LOG_COUNT - 1));
    volatile ts_entry_t *e = &s_ts_buf[core][idx];

    e->ticks = timer_now();
    e->tag   = tag;
    e->arg   = 0;
    ts_entry_clear_ext(e);

    e->kind        = TS_KIND_NVME_PDU;
    e->pdu_type    = info->pdu_type;
    e->hlen        = info->hlen;
    e->pdo         = info->pdo;
    e->pdu_len     = info->plen;
    e->cid         = info->cid;
    e->opcode      = info->opcode;
    e->sgl_type    = info->sgl_type;
    e->status      = info->status;
    e->cccid       = info->cccid;
    e->ttag        = info->ttag;
    e->data_offset = info->data_offset;
    e->data_length = info->data_length;

    s_ts_total[core]++;
}

void ts_log_rdma(uint32_t tag, const volatile ts_rdma_t *info)
{
    unsigned core = smp_core_index();
    if (s_ts_paused[core]) return;
    uint32_t   idx = (uint32_t)(s_ts_total[core] & (TS_LOG_COUNT - 1));
    volatile ts_entry_t *e = &s_ts_buf[core][idx];

    e->ticks = timer_now();
    e->tag   = tag;
    e->arg   = 0;
    ts_entry_clear_ext(e);

    e->kind        = TS_KIND_RDMA;
    e->pdu_type    = info->rdma_op;
    e->opcode      = info->wqe_cqe_opcode;
    e->hlen        = info->ds_cnt;
    e->status      = info->syndrome;
    e->pdu_len     = info->qpn;
    e->ttag        = info->counter;
    e->data_length = info->len;
    e->data_offset = info->remote_addr;
    e->cid         = (uint16_t)(info->remote_rkey >> 16);
    e->cccid       = (uint16_t)info->remote_rkey;

    s_ts_total[core]++;
}

void ts_log_tcp_ack(uint32_t tag, uint8_t conn_slot, uint32_t seq,
                     uint32_t ack_seq, uint32_t window, uint16_t flags)
{
    unsigned core = smp_core_index();
    if (s_ts_paused[core]) return;
    uint32_t   idx = (uint32_t)(s_ts_total[core] & (TS_LOG_COUNT - 1));
    volatile ts_entry_t *e = &s_ts_buf[core][idx];

    e->ticks = timer_now();
    e->tag   = tag;
    e->arg   = 0;
    ts_entry_clear_ext(e);

    e->kind        = TS_KIND_TCP_ACK;
    e->conn_slot   = conn_slot;
    e->tcp_seq     = seq;
    e->tcp_ack_seq = ack_seq;
    e->tcp_window  = window;
    e->tcp_flags   = flags;

    s_ts_total[core]++;
}

static const char *ts_file_name(uint8_t f)
{
    switch (f) {
    case TS_FILE_TCP:        return "tcp.c";
    case TS_FILE_NVME:       return "nvme.c";
    case TS_FILE_MLX5_NET:   return "mlx5_net.c";
    case TS_FILE_NVMET:      return "nvmet.c";
    case TS_FILE_NVMET_TCP:  return "nvmet_tcp.c";
    case TS_FILE_MLX5_QP:    return "mlx5_qp.c";
    case TS_FILE_ETH:        return "eth.c";
    case TS_FILE_NVME_TCP:   return "nvme_tcp.c";
    case TS_FILE_NVMET_RDMA: return "nvmet_rdma.c";
    default:                 return "?";
    }
}

static const char *ts_func_name(uint8_t f)
{
    switch (f) {
    case TS_FUNC_tcp_send_segment:       return "tcp_send_segment";
    case TS_FUNC_tcp_send:               return "tcp_send";
    case TS_FUNC_tcp_recv_internal:      return "tcp_recv_internal";
    case TS_FUNC_tcp_input:              return "tcp_input";
    case TS_FUNC_tcp_async_poll:         return "tcp_async_poll";
    case TS_FUNC_tcp_async_short_poll:   return "tcp_async_short_poll";
    case TS_FUNC_tcp_send_async_enqueue: return "tcp_send_async_enqueue";
    case TS_FUNC_tcp_send_async_short:   return "tcp_send_async_short";
    case TS_FUNC_nvme_read_pipelined_run:   return "nvme_read_pipelined_run";
    case TS_FUNC_nvme_write_pipelined_run:  return "nvme_write_pipelined_run";
    case TS_FUNC_nvme_pipeline_read_rx_tick:return "nvme_pipeline_read_rx_tick";
    case TS_FUNC_nvme_pipeline_rx_tick:     return "nvme_pipeline_rx_tick";
    case TS_FUNC_nvme_pipeline_h2c_pump:    return "nvme_pipeline_h2c_pump";
    case TS_FUNC_nvme_connect_job_step:     return "nvme_connect_job_step";
    case TS_FUNC_nvme_exec_step:            return "nvme_exec_step";
    case TS_FUNC_mlx5_net_post_frame:       return "mlx5_net_post_frame";
    case TS_FUNC_mlx5_net_post_lso_frame:   return "mlx5_net_post_lso_frame";
    case TS_FUNC_mlx5_net_sq_wait_room:     return "mlx5_net_sq_wait_room";
    case TS_FUNC_mlx5_net_try_recover:      return "mlx5_net_try_recover";
    case TS_FUNC_mlx5_wqe_analyze:          return "mlx5_wqe_analyze";
    case TS_FUNC_mlx5_net_send_frags:       return "mlx5_net_send_frags";
    case TS_FUNC_mlx5_net_send_frags_async: return "mlx5_net_send_frags_async";
    case TS_FUNC_mlx5_net_send_lso_async:   return "mlx5_net_send_lso_async";
    case TS_FUNC_mlx5_net_sq_reap_one:      return "mlx5_net_sq_reap_one";
    case TS_FUNC_mlx5_net_poll_recv:        return "mlx5_net_poll_recv";
    case TS_FUNC_nvmet_admin_dispatch:      return "nvmet_admin_dispatch";
    case TS_FUNC_nvmet_io_dispatch_cmd:     return "nvmet_io_dispatch_cmd";
    case TS_FUNC_nvmet_io_dispatch_h2c:     return "nvmet_io_dispatch_h2c";
    case TS_FUNC_nvmet_io_job_step_impl:    return "nvmet_io_job_step_impl";
    case TS_FUNC_nvmet_admin_job_step:      return "nvmet_admin_job_step";
    case TS_FUNC_nvmet_io_rx_upcall:        return "nvmet_io_rx_upcall";
    case TS_FUNC_nvmet_tcp_recv_cmd:        return "nvmet_tcp_recv_cmd";
    case TS_FUNC_nvmet_tcp_recv_cmd_body:   return "nvmet_tcp_recv_cmd_body";
    case TS_FUNC_nvmet_tcp_send_c2h:        return "nvmet_tcp_send_c2h";
    case TS_FUNC_nvmet_tcp_send_c2h_async:  return "nvmet_tcp_send_c2h_async";
    case TS_FUNC_nvmet_tcp_send_icresp:     return "nvmet_tcp_send_icresp";
    case TS_FUNC_nvmet_tcp_send_r2t:        return "nvmet_tcp_send_r2t";
    case TS_FUNC_nvmet_tcp_send_resp:       return "nvmet_tcp_send_resp";
    case TS_FUNC_mlx5_qp_post_send:         return "mlx5_qp_post_send";
    case TS_FUNC_mlx5_qp_post_send_ud:      return "mlx5_qp_post_send_ud";
    case TS_FUNC_mlx5_qp_post_rdma_common:  return "mlx5_qp_post_rdma_common";
    case TS_FUNC_mlx5_qp_post_recv:         return "mlx5_qp_post_recv";
    case TS_FUNC_mlx5_qp_post_recv_gsi:     return "mlx5_qp_post_recv_gsi";
    case TS_FUNC_mlx5_qp_poll_cqe:          return "mlx5_qp_poll_cqe";
    case TS_FUNC_mlx5_qp_poll_cqe_gsi:      return "mlx5_qp_poll_cqe_gsi";
    case TS_FUNC_eth_dump_tx_ring_debug:    return "eth_dump_tx_ring_debug";
    case TS_FUNC_eth_tx_queue:              return "eth_tx_queue";
    case TS_FUNC_nvme_tcp_recv_poll:        return "nvme_tcp_recv_poll";
    case TS_FUNC_nvmet_rdma_job_step:       return "nvmet_rdma_job_step";
    default:                                return "?";
    }
}

static const char *ts_nvme_tcp_pdu_type_str(uint8_t type)
{
    switch (type) {
    case NVME_TCP_PDU_ICREQ:    return "ICREQ";
    case NVME_TCP_PDU_ICRESP:   return "ICRESP";
    case NVME_TCP_PDU_H2C_TERM: return "H2C_TERM";
    case NVME_TCP_PDU_C2H_TERM: return "C2H_TERM";
    case NVME_TCP_PDU_CMD:      return "CMD";
    case NVME_TCP_PDU_RSP:      return "RSP";
    case NVME_TCP_PDU_H2C_DATA: return "H2C_DATA";
    case NVME_TCP_PDU_C2H_DATA: return "C2H_DATA";
    case NVME_TCP_PDU_R2T:      return "R2T";
    default:                    return "UNKNOWN";
    }
}

static const char *ts_rdma_op_str(uint8_t op)
{
    switch (op) {
    case TS_RDMA_OP_SQ_SEND:       return "SQ_SEND";
    case TS_RDMA_OP_SQ_RDMA_WRITE: return "SQ_RDMA_WRITE";
    case TS_RDMA_OP_SQ_RDMA_READ:  return "SQ_RDMA_READ";
    case TS_RDMA_OP_RQ_POST:       return "RQ_POST";
    case TS_RDMA_OP_CQE:           return "CQE";
    case TS_RDMA_OP_CQE_ERR:       return "CQE_ERR";
    case TS_RDMA_OP_CMD_RECV:      return "CMD_RECV";
    default:                       return "UNKNOWN";
    }
}

static void ts_print_entry(uint64_t n, const ts_entry_t *e, uint32_t delta_us)
{
    uart_printf("  #%8u tick=%08x%08x delta=%8uus tag=0x%08x %s:%s#%u arg=0x%08x",
                (uint32_t)n, (uint32_t)(e->ticks >> 32), (uint32_t)e->ticks,
                delta_us, e->tag,
                ts_file_name(TS_TAG_FILE(e->tag)), ts_func_name(TS_TAG_FUNC(e->tag)),
                (unsigned)TS_TAG_INFO(e->tag), e->arg);

    if (e->kind == TS_KIND_NVME_PDU) {
        uart_printf(" CH: TYPE=%s(0x%02x) HLEN=%u PDO=%u PLEN=%u",
                    ts_nvme_tcp_pdu_type_str(e->pdu_type), e->pdu_type,
                    e->hlen, e->pdo, e->pdu_len);
        switch (e->pdu_type) {
        case NVME_TCP_PDU_CMD:
            uart_printf(" PSH: CID=%u OPCODE=0x%02x SGLTYPE=0x%02x LEN=%u",
                        e->cid, e->opcode, e->sgl_type, e->data_length);
            break;
        case NVME_TCP_PDU_RSP:
            uart_printf(" PSH: CID=%u STATUS=0x%04x", e->cid, e->status);
            break;
        case NVME_TCP_PDU_R2T:
            uart_printf(" PSH: CCCID=%u TTAG=%u R2TO=%u R2TL=%u",
                        e->cccid, e->ttag, e->data_offset, e->data_length);
            break;
        case NVME_TCP_PDU_H2C_DATA:
        case NVME_TCP_PDU_C2H_DATA:
            uart_printf(" PSH: CCCID=%u TTAG=%u DATAO=%u DATAL=%u",
                        e->cccid, e->ttag, e->data_offset, e->data_length);
            break;
        default:
            uart_printf(" PSH: CID=%u CCCID=%u STATUS=0x%04x DATAO=%u DATAL=%u TTAG=%u",
                        e->cid, e->cccid, e->status, e->data_offset, e->data_length, e->ttag);
            break;
        }
    } else if (e->kind == TS_KIND_TCP_ACK) {
        uart_printf(" TCP: CONN=%u SEQ=%u ACK=%u WIN=%u FLAGS=0x%04x",
                    e->conn_slot, e->tcp_seq, e->tcp_ack_seq, e->tcp_window, e->tcp_flags);
    } else if (e->kind == TS_KIND_RDMA) {
        uart_printf(" RDMA: OP=%s QPN=%u CTR=%u WQE/CQE_OP=0x%x",
                    ts_rdma_op_str(e->pdu_type), e->pdu_len, e->ttag, e->opcode);
        switch (e->pdu_type) {
        case TS_RDMA_OP_SQ_SEND:
            uart_printf(" DS_CNT=%u LEN=%u", e->hlen, e->data_length);
            break;
        case TS_RDMA_OP_SQ_RDMA_WRITE:
        case TS_RDMA_OP_SQ_RDMA_READ:
            uart_printf(" DS_CNT=%u LEN=%u RADDR=0x%08x RKEY=0x%04x%04x",
                        e->hlen, e->data_length, e->data_offset, e->cid, e->cccid);
            break;
        case TS_RDMA_OP_RQ_POST:
            uart_printf(" LEN=%u", e->data_length);
            break;
        case TS_RDMA_OP_CQE:
            uart_printf(" BYTE_CNT=%u", e->data_length);
            break;
        case TS_RDMA_OP_CQE_ERR:
            uart_printf(" SYNDROME=0x%02x", e->status);
            break;
        case TS_RDMA_OP_CMD_RECV:
            uart_printf(" CID=%u LEN=%u", e->data_offset, e->data_length);
            break;
        default:
            break;
        }
    }

    uart_printf("\n");
}

// 現在有効な(まだ上書きされていない)エントリの通し番号の下限を返す。
static uint64_t ts_first_valid(uint64_t total)
{
    uint32_t avail = (total < TS_LOG_COUNT) ? (uint32_t)total : (uint32_t)TS_LOG_COUNT;
    return total - avail;
}

uint64_t ts_log_query_start_last_n(unsigned core, uint32_t count)
{
    if (core >= SMP_MAX_CORES) core = 0;
    uint64_t total = s_ts_total[core];
    uint64_t first = ts_first_valid(total);
    uint64_t avail = total - first;
    if (count > avail) count = (uint32_t)avail;
    return total - count;
}

uint64_t ts_log_query_start_last_n_matching(unsigned core, uint32_t mask, uint32_t value, uint32_t count)
{
    if (core >= SMP_MAX_CORES) core = 0;
    uint64_t total = s_ts_total[core];
    uint64_t first = ts_first_valid(total);
    if (count == 0) return total;

    uint32_t remaining = count;
    uint64_t n = total;
    while (n > first) {
        n--;
        uint32_t idx = (uint32_t)(n & (TS_LOG_COUNT - 1));
        if ((s_ts_buf[core][idx].tag & mask) == value) {
            remaining--;
            if (remaining == 0) return n;
        }
    }
    return first;  // 一致がcount件に満たない場合は保持範囲の先頭から
}

void ts_log_dump_core(unsigned core, uint64_t start, uint32_t count, uint32_t mask, uint32_t value)
{
    if (core >= SMP_MAX_CORES) core = 0;
    uint64_t total = s_ts_total[core];
    uint64_t first = ts_first_valid(total);
    if (start < first) start = first;
    if (start > total) start = total;

    uart_printf("ts: core=%u start=#%u count=%u", core, (uint32_t)start, count);
    if (mask != 0) {
        uart_printf(" mask=0x%08x value=0x%08x", mask, value);
    }
    uart_printf(" (保持範囲#%u〜#%u)\n",
                (uint32_t)first, (uint32_t)(total > 0 ? total - 1 : 0));

    uint64_t prev_ticks = 0;
    int      have_prev  = 0;
    uint32_t shown       = 0;
    for (uint64_t n = start; n < total && shown < count; n++) {
        uint32_t   idx = (uint32_t)(n & (TS_LOG_COUNT - 1));
        ts_entry_t e   = s_ts_buf[core][idx];
        if (mask != 0 && (e.tag & mask) != value) {
            continue;  // mask絞り込み中は不一致をスキップ(deltaの基準にもしない)
        }

        uint32_t delta_us = 0;
        if (have_prev) {
            delta_us = (uint32_t)ticks_to_us(e.ticks - prev_ticks);
        }

        ts_print_entry(n, &e, delta_us);

        prev_ticks = e.ticks;
        have_prev  = 1;
        shown++;
    }
    if (shown == 0) {
        uart_printf("ts: 該当エントリなし\n");
    }
}

static ts_entry_t s_ts_frozen[SMP_MAX_CORES][TS_FREEZE_COUNT] __attribute__((aligned(64)));
static uint64_t   s_ts_frozen_start_n[SMP_MAX_CORES];  // フリーズした先頭エントリの通し番号
static uint32_t   s_ts_frozen_count[SMP_MAX_CORES];    // 実際にフリーズした件数(TS_FREEZE_COUNT以下)
static int        s_ts_frozen_valid[SMP_MAX_CORES];

void ts_log_freeze(void)
{
    unsigned core     = smp_core_index();
    uint64_t total    = s_ts_total[core];
    uint64_t first    = ts_first_valid(total);
    uint64_t avail64  = total - first;
    uint32_t count    = (avail64 < TS_FREEZE_COUNT) ? (uint32_t)avail64 : TS_FREEZE_COUNT;
    uint64_t start    = total - count;

    for (uint32_t i = 0; i < count; i++) {
        uint32_t idx = (uint32_t)((start + i) & (TS_LOG_COUNT - 1));
        s_ts_frozen[core][i] = s_ts_buf[core][idx];
    }
    s_ts_frozen_start_n[core] = start;
    s_ts_frozen_count[core]   = count;
    s_ts_frozen_valid[core]   = 1;
}

void ts_log_set_paused_core(unsigned core, int paused)
{
    if (core >= SMP_MAX_CORES) core = 0;
    s_ts_paused[core] = paused;
}

uint32_t g_ts_log_mode = 0x1;
inline uint32_t ts_log_mode(void)
{
    return g_ts_log_mode;
}

void  ts_log_mode_set(uint32_t mode)
{
    g_ts_log_mode = mode;
}
