// timestamp.c
//
// 性能分析用の軽量タイムスタンプロガー(timestamp.h参照)。
// リングバッファ本体はCPUのみが読み書きする通常のBSS(DMA対象ではない
// ためcache化されたNormal RAMのままでよく、.dma_bss不要 -- CLAUDE.md
// 「MMUは有効」節参照)。

#include "timestamp.h"
#include "timer.h"
#include "uart.h"
#include "nvme_tcp_pdu.h"  // NVME_TCP_PDU_* -- pdu_typeの文字列化にのみ使う
#include "smp.h"

// マルチコア化 Phase 3(~/.claude/plans/wondrous-baking-gadget.md参照):
// リングバッファ・累計カウンタ・一時停止フラグをコアごとに独立配列化
// した(timestamp.hのヘッダコメント参照)。各関数の先頭でsmp_core_
// index()を1回呼び、以後はその添字の配列だけを触る。
static ts_entry_t s_ts_buf[SMP_MAX_CORES][TS_LOG_COUNT] __attribute__((aligned(64)));
static uint64_t   s_ts_total[SMP_MAX_CORES];  // 単調増加、ts_log*()の累計呼び出し回数
static volatile int s_ts_paused[SMP_MAX_CORES];  // 1の間はts_log*()系が即座に何もせず返る

_Static_assert(sizeof(ts_entry_t) == TS_LOG_ENTRY_BYTES,
               "ts_entry_t must be exactly 64 bytes");

// e->kind以外の全拡張フィールドを0クリアする(kind自体はTS_KIND_PLAINに
// 設定する -- 呼び出し元が別のkindを使うならこの直後に上書きする)。
// リングバッファの同じスロットを異なる記録関数が使い回すため、前回
// そのスロットに書かれた拡張フィールドの残骸が残らないようにする目的
// (s_ts_buf自体はBSSで起動時に一度だけ0クリアされるが、以後は上書きの
// たびに明示的にクリアしないと古いkindの値が透けて見えてしまう)。
//
// eはvolatile経由で受け取る -- 実機で発見した本物のバグ(2026-08-02):
// 非volatileだとGCC -O2が隣接フィールドへの逐次代入(pdu_len@28+
// data_offset@32等)を1回の8バイトstur命令へ結合することがあり、
// s_ts_buf自体は64バイトアラインでもフィールドオフセット28は8バイト
// 境界に乗らないため、結合後のストアが実機でAlignment fault
// (esr=0x96000061、DFSC=0x21)を起こした。net.h/CLAUDE.md「ローカル
// スクラッチバッファへの逐次1バイト代入もvolatileが必須」節と同じ
// クラスのバグ(バイト単位に限らずフィールド単位の逐次代入全般に
// 当てはまることが今回判明した)。
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

uint64_t ts_log_total(void)
{
    return s_ts_total[smp_core_index()];
}

// tagの4バイト全てが印字可能ASCII(0x20-0x7e)ならout[0..3]+NULへ書き1を
// 返す。そうでなければ0を返す(呼び出し側はASCII表示を省略すればよい)。
// outはvolatile経由のバイト単位アクセスで書く -- 素のchar配列に対する
// 連続した1バイトずつの代入は、コンパイラが1回のワイドストアへ結合
// することがあり、その結合先アドレスがバッファの実際のスタック配置
// (自然アラインは1バイトのまま)によっては非アラインになりうる。実機で
// これがAlignment fault(Synchronous, data abort, ESR DFSC=Alignment
// fault)を引き起こした実績がある -- net.h/arp.cの多バイトフィールド
// アクセスがvolatile経由のバイト単位アクセスに統一されているのと同じ
// 理由(CLAUDE.md参照)。 */
// File#(tag bit[31:24]) を人間可読なファイル名にする(timestamp.hの
// TS_FILE_*と対応)。未知は"?"。
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

// Func#(tag bit[23:16]) を人間可読な関数名にする(timestamp.hのTS_FUNC_*と
// 対応)。未知は"?"。
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

// pdu_type(nvme_tcp_pdu.hのNVME_TCP_PDU_*)を人間可読な文字列にする。
// 未知の値は"UNKNOWN"を返す(呼び出し元はkind==TS_KIND_NVME_PDUのときだけ
// これを呼ぶので、TS_KIND_PLAIN/TS_KIND_TCP_ACKのエントリのpdu_type==0
// [NVME_TCP_PDU_ICREQと同値]をここで解釈することはない)。
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

// rdma_op(timestamp.hのTS_RDMA_OP_*)を人間可読な文字列にする。
// 未知の値は"UNKNOWN"を返す(呼び出し元はkind==TS_KIND_RDMAのときだけ
// これを呼ぶ)。
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

// 1エントリを表示する共通処理(ts_log_dump_core()が使う)。deltaは
// 呼び出し側が既に計算済みの値をそのまま表示するだけ(「直前の記録順
// エントリとの差」か「直前の一致エントリとの差」かはts_log_dump_core()
// 側の責務)。kindに応じてNVMe/TCP PDUまたはTCP ACK/Window Updateの詳細を
// 2行目として追加表示する。
static void ts_print_entry(uint64_t n, const ts_entry_t *e, uint32_t delta_us)
{
    /* tag = File#[31:24] | Func#[23:16] | info[15:0](timestamp.h参照)。
     * File名:Func名#info の形で表示する。kindがTS_KIND_NVME_PDU/
     * TS_KIND_TCP_ACK/TS_KIND_RDMAなら、改行せず同じ行の末尾に詳細を
     * 追記する(grep/画面幅の都合で改行しない方が見やすいという要望に
     * 合わせた設計)。 */
    uart_printf("  #%8u tick=%08x%08x delta=%8uus tag=0x%08x %s:%s#%u arg=0x%08x",
                (uint32_t)n, (uint32_t)(e->ticks >> 32), (uint32_t)e->ticks,
                delta_us, e->tag,
                ts_file_name(TS_TAG_FILE(e->tag)), ts_func_name(TS_TAG_FUNC(e->tag)),
                (unsigned)TS_TAG_INFO(e->tag), e->arg);

    if (e->kind == TS_KIND_NVME_PDU) {
        /* CH(全PDU種別共通、nvme_tcp_hdr_t参照): 型・ヘッダ長・データ
         * オフセット・PDU全体長。PSHはpdu_typeに応じて意味が変わる
         * フィールドだけを、正しいラベルで続けて表示する(ts_nvme_pdu_tの
         * ドキュメント参照) -- 全種別で同じ9個のラベルを一律表示していた
         * 旧実装(無関係なフィールドが常に0として並ぶ)から変更した。 */
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
            /* ICReq/ICResp/Terminate等、PSHを個別対応していない種別
             * (mlx5_net.cのNDBG等、生のワイヤ値をそのまま渡す診断呼び出し
             * を含む) -- 判明している全フィールドを汎用表示する。 */
            uart_printf(" PSH: CID=%u CCCID=%u STATUS=0x%04x DATAO=%u DATAL=%u TTAG=%u",
                        e->cid, e->cccid, e->status, e->data_offset, e->data_length, e->ttag);
            break;
        }
    } else if (e->kind == TS_KIND_TCP_ACK) {
        uart_printf(" TCP: CONN=%u SEQ=%u ACK=%u WIN=%u FLAGS=0x%04x",
                    e->conn_slot, e->tcp_seq, e->tcp_ack_seq, e->tcp_window, e->tcp_flags);
    } else if (e->kind == TS_KIND_RDMA) {
        /* 全rdma_op共通: 種別・QPN・そのイベント時点のsq_pc/rq_pc/cq_cc
         * (ttag)・WQE/CQE opcode。以降はrdma_opに応じて意味が変わる
         * フィールドだけを続けて表示する(timestamp.hのts_rdma_tドキュ
         * メント参照)。 */
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
            /* WQE/CQE_OP列にはNVMeコマンドのopcodeが入っている(ts_rdma_t
             * ドキュメント参照、wqe_cqe_opcodeフィールドの流用)。 */
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

uint64_t ts_log_query_start_after_tick(unsigned core, uint64_t tick)
{
    if (core >= SMP_MAX_CORES) core = 0;
    uint64_t total = s_ts_total[core];
    uint64_t first = ts_first_valid(total);

    /* リングバッファはts_log()が常にtimer_now()の昇順で追記していく
     * 設計(エントリ間でtickが逆転することはない)ため、保持範囲を先頭
     * から線形に走査してtickを超えた最初のエントリを見つけるだけでよい
     * (ts_log_query_start_last_n_matching()のような後方走査は不要)。 */
    uint64_t n;
    for (n = first; n < total; n++) {
        uint32_t idx = (uint32_t)(n & (TS_LOG_COUNT - 1));
        if (s_ts_buf[core][idx].ticks > tick) {
            break;
        }
    }
    return n;  // n==totalなら「該当なし」(ts_log_dump_core()に渡すと0件表示になる)
}

uint64_t ts_log_query_start_last_n_matching(unsigned core, uint32_t mask, uint32_t value, uint32_t count)
{
    if (core >= SMP_MAX_CORES) core = 0;
    uint64_t total = s_ts_total[core];
    uint64_t first = ts_first_valid(total);
    if (count == 0) return total;

    /* 後方(新しい方)から走査し、(tag & mask)==value がcount件見つかった
     * 時点の通し番号を返す -- ts_log_dump_core()がそこから前方走査して
     * 同じ条件で数えれば、ちょうど直近count件(またはそれ未満、保持範囲
     * 全体で数えても足りない場合)を表示できる。 */
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

/* coreのリングバッファのstart(通し番号 -- 上記ts_log_query_start_*()の
 * 戻り値、または呼び出し側が`ts start <N> end <N>`のように直接指定した
 * 値)から、tagが0なら無条件に、0以外ならtag一致するものだけを、最大
 * count件表示する。startが現在保持している範囲の外にあっても自動的に
 * クランプする。
 *
 * command.cの`ts`コマンドはどのモードでも必ず「オプション解析→(必要なら)
 * 上記query関数で開始番号を問い合わせる→この関数を呼ぶ」という同じ
 * 2段階の流れになる(2026-08-08、ユーザー指示 -- 以前はモードごとに
 * 個別の表示関数(件数版/範囲版/tick版/タグ版)を持っていて、走査ロジックと
 * 表示ロジックの両方が4箇所に重複していた)。 */
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

// フリーズ用の別バッファ(timestamp.hのTS_FREEZE_COUNTコメント参照)。
// s_ts_buf本体とは独立しており、ts_log()の以後の呼び出しでは一切
// 上書きされない -- CPUのみが読み書きする通常のBSSでよい(s_ts_buf自体
// と同じ理由、DMA対象ではない)。マルチコア化 Phase 3により、こちらも
// コアごとに独立配列化した(ts_log_freeze()は「呼び出したコア自身の
// フリーズ状態」だけを触る、ts_log_dump_frozen_core()は明示的に指定した
// コアのフリーズ状態を読む)。
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

// 2026-08-08、ユーザー指示(mlx5 core分離のタイムアウト根本原因調査)で
// ts_log_dump_core()と同じパターンへリファクタ -- PF0(core0)/PF1(core1)
// それぞれが自コアでts_log_freeze()した内容を、常にcore0から動く
// シェル(command.c)側で両方とも読み比べられるようにする。
void ts_log_dump_frozen_core(unsigned core, uint32_t count)
{
    if (!s_ts_frozen_valid[core] || s_ts_frozen_count[core] == 0) {
        uart_printf("ts: core=%u フリーズ済みスナップショット無し"
                    "(ts_log_freeze()が未実行、またはフリーズ時点で記録0件)\n", core);
        return;
    }
    if (count > s_ts_frozen_count[core]) {
        count = s_ts_frozen_count[core];
    }
    uint32_t start_i = s_ts_frozen_count[core] - count;

    uart_printf("ts: core=%u フリーズ済みスナップショット 直近%u件/%u件 "
                "(freeze時点の通し番号#%u〜#%u)\n",
                core, count, s_ts_frozen_count[core],
                (uint32_t)s_ts_frozen_start_n[core],
                (uint32_t)(s_ts_frozen_start_n[core] + s_ts_frozen_count[core] - 1));

    uint64_t prev_ticks = 0;
    int      have_prev  = 0;
    for (uint32_t i = start_i; i < s_ts_frozen_count[core]; i++) {
        ts_entry_t e = s_ts_frozen[core][i];

        uint32_t delta_us = 0;
        if (have_prev) {
            delta_us = (uint32_t)ticks_to_us(e.ticks - prev_ticks);
        }

        ts_print_entry(s_ts_frozen_start_n[core] + i, &e, delta_us);

        prev_ticks = e.ticks;
        have_prev  = 1;
    }
}

void ts_log_set_paused_core(unsigned core, int paused)
{
    if (core >= SMP_MAX_CORES) core = 0;
    s_ts_paused[core] = paused;
}

int ts_log_is_paused_core(unsigned core)
{
    if (core >= SMP_MAX_CORES) core = 0;
    return s_ts_paused[core];
}

void ts_log_set_paused(int paused)
{
    ts_log_set_paused_core(smp_core_index(), paused);
}

int ts_log_is_paused(void)
{
    return ts_log_is_paused_core(smp_core_index());
}

/* ts_log_modeのビット割り当て(詳細は timestamp.h の TS_MODE_HOTPATH 節):
 *   bit0(0x1): コマンドレベル/低頻度診断(既定ON)。
 *   bit1(0x2): nvmet.cのpush受信 per-CMD診断(既定OFF)。
 *   bit2(0x4=TS_MODE_HOTPATH): per-frame/per-segmentのRX/TXステージ計装
 *              (mlx5_net poll_recv・tcp_send_segment・tcp_input)。**既定OFF**。
 * 既定は0x1(bit0のみ)。
 *
 * 【2026-08-15、bit2を新設し per-frame計装を既定OFF化】従来 mlx5_net の
 * poll_recv per-frame ts_log(6回/フレーム)は無ガードで常時記録し、tcp_input/
 * tcp_send_segment の per-segment ログも bit0(既定ON)で記録していた。実機の
 * `ts pause` A/B(tcpbench 256 read)で、これらが受信ホットパスに約+19.7%の
 * オーバーヘッドを乗せていることが判明(51960→62190回/3s)。per-frame/
 * per-segment のみ bit2 へ移し既定OFFにすることで、コマンドレベルの安価な
 * トレース(bit0)は残しつつ受信スループットを回復させた。 */
uint32_t g_ts_log_mode = 0x1;
inline uint32_t ts_log_mode(void)
{
    return g_ts_log_mode;
}

void  ts_log_mode_set(uint32_t mode)
{
    g_ts_log_mode = mode;
}
