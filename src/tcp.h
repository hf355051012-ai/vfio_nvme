#ifndef TCP_H
#define TCP_H

#include <stdint.h>
#include <stddef.h>
#include "netif.h"
#include "smp.h"

/* ================================================================
 * tcp.h — TCP (RFC 793) 実装 — フェーズ5(Tier3: 輻輳制御・実RTT計測・
 * パイプライン送受信版)
 *
 * NVMe/TCP実装の前提となる、ポーリングベースのクライアント実装。
 * 同時に最大TCP_MAX_CONNS本(tcp.c参照、現在4)のコネクションを扱える —
 * tcp_input()は登録されている全アクティブconnをremote_ip/local_port/
 * remote_portで照合し、一致したものにディスパッチする(NVMe/TCPの
 * admin queue+IO queueが別々のTCPコネクションとして同時に生きることを
 * 想定した拡張)。tcp_conn_t自体は呼び出し側がスタック上に確保することが
 * ある小さな構造体のままにしてあり(下記コメント参照)、コネクションごとの
 * 大きな可変状態(受信循環バッファ、ACK追跡、RTT/輻輳ウィンドウ)は
 * tcp.c内部のプライベートなスロット配列(tcp_conn_tへのポインタと対応
 * するインデックスで紐付け)に保持する — スタックに直接持たせると
 * リンカスクリプトのスタック領域(64KB、linker.ld参照)を1個の
 * ローカル変数だけで枯渇させてしまうため。
 *
 * 「コア信頼性」として実装済み(段階的なRFC準拠強化の第1段階):
 *   - 受信セグメントのチェックサム検証(不正なら破棄)
 *   - RTOベースの再送(指数バックオフ。ただし固定初期値からのバックオフ
 *     のみで、RFC 6298のSRTT/RTTVARによる実RTT計測は未実装 — 次段階)
 *   - MSSに応じたセグメンテーション(tcp_send()が複数セグメントに分割)
 *   - 相手の広告ウィンドウに基づく実フロー制御(snd_win): 送信側
 *   - 自分の受信バッファ空き状況に基づく実ウィンドウ広告(RCV.WND): 受信側。
 *     受信バッファ(s_rx_buf)はtcp_recv()で取り出されるまで単一スロットしか
 *     持たないため、埋まっている間はwindow=0を広告して相手の送信を止め、
 *     tcp_recv()で取り出した直後に明示的なwindow更新ACKを送る。これが
 *     無かった旧実装では、相手が前のセグメントの取り出し前に次を送って
 *     きた場合にs_rx_bufが黙って上書きされデータが失われるバグがあった
 *     (実機のtcptestで8000バイト中1460バイト分の欠落として確認・特定)。
 *   - SYNへのMSSオプション付加、SYN-ACKからの相手側MSS解析
 *
 * 「Tier2」として実装済み(段階的なRFC準拠強化の第2段階):
 *   - CLOSE_WAIT/LAST_ACKの正しい遷移: 相手が先にFINを送ってきた受動close
 *     を、以前のように1ステップ(即座にFIN|ACKを返してCLOSED)へ圧縮せず、
 *     ESTABLISHED→(相手のFIN受信、ACKのみ返す)→CLOSE_WAIT→
 *     (tcp_close()呼び出しで自分のFIN送信)→LAST_ACK→
 *     (自分のFINがACKされる)→CLOSEDと正しく2段階にした。CLOSE_WAIT中は
 *     tcp_send()で送信を続けられる(半クローズ)。tcp_recv()が0を返すのは
 *     「相手の送信方向が閉じた(CLOSE_WAITに入った)」ことを意味し、
 *     コネクション全体の終了は意味しない — 呼び出し側は必要な送信を終えた
 *     上でtcp_close()を呼ぶこと。
 *   - シーケンス番号ラップアラウンド安全な比較(tcp_seq_lt/gt等、tcp.c)。
 *     32bitシーケンス番号の差分を符号付き整数として解釈する標準的な手法
 *     (Linuxカーネルのbefore()/after()と同じ考え方)。
 *   - 順序が入れ替わったセグメントの先読みバッファリング(tcp_priv_t.ooo[]、
 *     tcp.c)。ギャップのある(未来の)セグメントをTCP_OOO_SLOTS件まで
 *     同時に保持しておき、欠けていたセグメントが届いてギャップが埋まったら
 *     tcp_input()の中で自動的に繋げる(1件解決すると別のスロットが
 *     連鎖的に解決することもあるためループで確認する)。当初は1件だけの
 *     単一スロットだったが、実機のNVMe/TCPベンチマーク(16KB〜256KBの
 *     write)で複数セグメントが同時に順序を崩すケースが頻発し、1件を
 *     超えた分を保持できず相手の再送待ちを繰り返すことで性能が大きく
 *     劣化する事象を確認したため、複数スロット化した(詳細はtcp.cの
 *     TCP_OOO_SLOTSコメント参照)。
 *
 * 「Tier3」として実装済み(段階的なRFC準拠強化の第3段階 — tcpbenchでの
 * 実測でスループットの支配要因が「双方向ストップ&ウェイトによる往復
 * レイテンシ」だったことを受けて着手):
 *   - 送信側の真のパイプライン化(tcp_send()): 旧実装は1セグメント送る
 *     ごとにACKを待つストップ&ウェイトだったが、Go-Back-N方式の
 *     スライディングウィンドウへ変更。輻輳ウィンドウ(cwnd)と相手の
 *     広告ウィンドウの許す範囲で複数セグメントを連続送信し、累積ACKで
 *     一括して未確認区間(snd_una)を進める。RTOタイムアウト時は
 *     未確認区間全体を再送する(選択的再送/SACKは未実装)。
 *   - 輻輳制御(RFC 5681簡易版): スロースタート(cwnd<ssthresh の間、
 *     ACK進捗ごとに+1MSS)+輻輳回避(+MSS^2/cwnd、概ね+1MSS/RTT)。
 *     初期ウィンドウはRFC5681の公式 IW=min(4*MSS,max(2*MSS,4380))。
 *     ロスシグナルはRTOタイムアウトのみ(重複ACKによる高速再送/高速回復
 *     はSACK等の追加情報無しでは効果が薄く複雑になるため未実装)。
 *   - RTT実測(RFC 6298簡易版): SRTT/RTTVARを実測RTTから更新し
 *     (alpha=1/8, beta=1/4, K=4)、RTO=SRTT+4*RTTVARを動的に算出する。
 *     Karnのアルゴリズム(再送を経たセグメントのACKからは測定しない)を
 *     適用。tcp_connect()ごとにリセットする(前の接続の値を引き継がない)。
 *   - 受信バッファの循環バッファ化(TCP_RX_BUF_SIZE、tcp.c):
 *     旧実装は1セグメント分の単一スロットしか持てず、相手も実質
 *     ストップ&ウェイトを強いられていた。44セグメント分(約62.7KB、当初は
 *     8セグメント分だったがtcpbenchの実測でボトルネックと判明し拡張済み
 *     — 詳細はtcp.cのTCP_RX_BUF_SIZEコメント参照)の循環バッファに拡張し、
 *     実際の空き容量に応じたウィンドウを広告することで、相手も真に
 *     パイプライン送信できるようにした。順序入れ替わりの先読み
 *     バッファ(Tier2実装)も、循環バッファ化によりtcp_recv()の取り出しを
 *     待たずtcp_input()内でその場合流できるよう改善。
 *
 * 「Window Scaling」として実装済み(RFC 7323、2026-07-25追加 --
 *   NVMe/TCPで256KBの書き込みをR2T+H2CData 1ラウンドで受け取れるように
 *   する目的で着手。それまではTCP_RX_BUF_SIZEが16bitのwindowフィールド
 *   (上限65535)に収まる約62.7KBに抑えられており、より大きな転送は
 *   nvmet_tcp.c側で複数ラウンドに分割する必要があった):
 *   - Window Scaleオプション(kind=3, len=3, shift 1バイト)をSYN/SYN-ACKで
 *     交換する。RFC7323の規則通り、双方が自分のSYN(能動openは最初のSYN、
 *     受動openは相手のSYNへの返信であるSYN-ACK)にこのオプションを含めて
 *     初めて、そのコネクション全体でスケーリングが有効になる(片方だけが
 *     付けても無効のまま、tcp.cのpriv->wscale_enabled参照)。
 *   - 自分の受信ウィンドウのスケール係数(TCP_RCV_WSCALE)は固定値。
 *     相手の送信ウィンドウのスケール係数(相手のSYN/SYN-ACKから読み取る、
 *     tcp_priv_t.snd_wscale)は接続ごとに保持する。
 *   - SYN/SYN-ACK自身のwindowフィールドは(RFC7323の規定通り)スケーリング
 *     しない -- ハンドシェイク完了後の全セグメントにのみ適用する
 *     (tcp_input()内の適用順序で自然に実現している、tcp.cのコメント参照)。
 *   - スケーリングが不成立(相手がオプションを付けてこなかった)コネクション
 *     は、TCP_RX_BUF_SIZEが65535を超えていても常に生の16bit値(65535で
 *     クランプ)のまま広告する -- 旧実装からの後方互換。
 *
 * 未実装(将来の課題):
 *   - 選択的確認応答(SACK)、それに基づく選択的再送(現状はGo-Back-Nで
 *     未確認区間全体を再送する)
 *   - 重複ACKに基づく高速再送/高速回復(RTOを伴わないより穏やかな輻輳
 *     ウィンドウ半減)
 *   - タイムスタンプオプション(RFC7323のもう一方の柱、RTTM/PAWS用 --
 *     本実装はタイムスタンプに頼らない簡易RTT計測(Tier3参照)のままで、
 *     必要になるまで見送る)
 * ================================================================ */

/* テレメトリ用の統計カウンタ(tcpbench等が使う)。tcp_send_reliable()が
 * RTO満了で再送するたびにインクリメントされる -- パケットロス相当の
 * 指標として使える(このプロジェクトはTCP層で直接パケットロスを検知
 * する手段を持たないため、RTOタイムアウト発生をその代理指標とする)。
 * マルチコア化 Phase 4(~/.claude/plans/wondrous-baking-gadget.md参照)
 * によりコアごとに独立配列化した -- 呼び出し側はsmp.hのsmp_core_index()
 * で自コア分を参照すること(bench.c参照)。 */
extern volatile uint32_t g_tcp_retransmit_count[SMP_MAX_CORES];
extern volatile uint32_t g_tcp_ack_threshold;

/* 受信循環バッファ(TCP_RX_BUF_SIZE)の容量を返す。パイプライン受信
 * (nvme_read_pipelined_run)が in-flight を rx_buf 未満に抑えるために使う。 */
uint32_t tcp_rx_buf_size(void);

/* シェルからのCtrl+C(0x03)割り込み要求。tcp_poll_once()(このプロジェクト
 * のあらゆる長時間ブロックする待ちループから頻繁に呼ばれる、tcp.c内部の
 * 共通ポーリング関数)が毎回UARTの未読バイトを確認し、Ctrl+Cを検出すると
 * このフラグを立てる。`nvmet`のように接続が切れるまでシェルへ戻らない
 * コマンドが、切断を待たずユーザの意思で中断できるようにするための
 * 機構(以前は`nvmet`がハングすると電源を入れ直すしかなかった)。
 *
 * tcp_recv_internal()/nvmet_tcp_recv_exact()/tcp_send()/tcp_send_reliable()/
 * tcp_accept_wait()/nvmet_io_loop()等、長時間ブロックしうる待ちループは
 * これを定期的に確認し、立っていれば速やかに処理を中断して呼び出し元へ
 * 戻ること(既存のタイムアウト/失敗パスをそのまま流用してよい箇所が多い)。
 * command.cのdispatch()がコマンド呼び出し直前に必ずクリアする -- クリア
 * し忘れると前回のCtrl+Cが次の無関係なコマンドを即座に中断してしまう。 */
int  tcp_abort_requested(void);
void tcp_clear_abort_request(void);

#define TCP_HDR_LEN 20u

/* フラグ(byteの下位6bit) */
#define TCP_FLAG_FIN 0x01u
#define TCP_FLAG_SYN 0x02u
#define TCP_FLAG_RST 0x04u
#define TCP_FLAG_PSH 0x08u
#define TCP_FLAG_ACK 0x10u
#define TCP_FLAG_URG 0x20u

/* TCPヘッダ(20バイト、オプション無し)。
 * 多バイトフィールドへの直接アクセスは行わないこと — 必ず
 * net.h の rd16be/rd32be/wr16be/wr32be 経由でアクセスする
 * (data_offset/flagsは1バイト単体なので対象外)。 */
typedef struct __attribute__((packed)) {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t  data_offset;  /* 上位4bit = ヘッダ長(32bitワード数、オプション無しなら5)。下位4bitは予約(0) */
    uint8_t  flags;        /* 下位6bit使用: URG ACK PSH RST SYN FIN (TCP_FLAG_*参照) */
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
} tcp_header_t;

typedef enum {
    TCP_CLOSED,
    TCP_SYN_SENT,
    TCP_ESTABLISHED,
    TCP_FIN_WAIT_1,
    TCP_FIN_WAIT_2,
    TCP_TIME_WAIT,
    TCP_CLOSE_WAIT,  /* 相手が先にFINを送ってきた(受動close側)。tcp_send()で
                       * 送信を続けられる(半クローズ)。tcp_close()を呼ぶと
                       * 自分のFINを送りLAST_ACKへ進む。 */
    TCP_LAST_ACK,     /* CLOSE_WAIT中にtcp_close()を呼び、自分のFINへの
                       * ACKを待っている状態。ACKされたらCLOSEDへ。 */
    TCP_SYN_RCVD,     /* tcp_accept()側(受動open)。相手のSYNを受けSYN|ACKを
                       * 返し、相手のACKを待っている状態。ACKを受けると
                       * ESTABLISHEDへ進む。 */
} tcp_state_t;

/* 全フィールドをvolatile指定する理由: tcp_conn_tは常にポインタ経由
 * (tcp_connect()等の引数)でアクセスされ、実体は呼び出し元(スタック上
 * またはstatic)が所有する。実体を直接操作する関数(tcp_connect()等)は、
 * その配置(8バイト境界に乗るかどうか)を一切コントロールできない。
 * tcp_conn_t自体の宣言上のアラインメントはuint32_tフィールドにより4バイト
 * までしか保証されないため、-O2最適化でコンパイラが隣接フィールド
 * (発見時の実例: rcv_seq(4B)+snd_win(2B、当時)+snd_mss(2B)の計8バイト)を
 * 1回の8バイトストアへ結合すると、そのオフセットが8バイト境界に乗って
 * いない場合にMMU無効環境でAlignment faultになる(実機で発生・re解析済み
 * — offset20からの8バイトstur命令がrcv_seq/snd_win/snd_mssを結合していた)。
 * snd_winは2026-07-25にWindow Scaling対応でuint32_tへ拡張したが、
 * この防御自体はフィールドサイズに依らない(volatileが型システムレベルで
 * あらゆる隣接フィールドの結合を禁止するため)ので変更不要。
 * net.hのrd16be/wr16be等がパック構造体(ワイヤフォーマット)に対して
 * volatileバイトアクセスを強制するのと同じ防御を、この非パック構造体の
 * フィールド単位で適用する(隣接フィールドの結合を型システムレベルで
 * 禁止する)。 */
typedef struct {
    volatile tcp_state_t state;
    volatile uint32_t    local_ip;
    volatile uint32_t    remote_ip;
    volatile uint16_t    local_port;
    volatile uint16_t    remote_port;
    volatile uint32_t    snd_seq;   /* 次に送るシーケンス番号 */
    volatile uint32_t    rcv_seq;   /* 次に期待する受信シーケンス番号 */
    volatile uint32_t    snd_win;   /* SND.WND: 相手が広告した現在の受信ウィンドウ(動的、
                             * 受信した全セグメントのwindowフィールドで更新される)。
                             * tcp_send()の分割サイズを制限するのに使う。Window
                             * Scaling(RFC7323)が成立したコネクションでは、ワイヤ上の
                             * 16bit値を相手のスケール係数だけ左シフトした実際の
                             * バイト数を保持するため、フィールド自体は32bit
                             * (旧版はuint16_t、2026-07-25拡張)。 */
    volatile uint16_t    snd_mss;   /* 相手へ送る1セグメントの最大データ長。ハンドシェイク中に
                             * 相手のSYN-ACKのMSSオプションから解決される
                             * (無ければRFC879既定の536、自分のバッファ容量で上限あり)。 */
    /* このコネクションのs_conns[]/s_priv[]スロットが実際に置かれている
     * コア(マルチコア化 Phase 4-6準備、~/.claude/plans/wondrous-baking-
     * gadget.md「job stepのctx経由リソース参照化」節参照)。
     * tcp_connect_begin()/tcp_input()の受動openパスが、そのコネクション
     * を実際に登録した瞬間のsmp_core_index()を書き込む。tcp_priv_for()/
     * tcp_conn_slot()等、conn(tcp_conn_t*)からs_priv[]/s_conns[]の
     * スロットを逆引きする全ての関数は、呼び出し時点のsmp_core_index()
     * (=「今このコードを実行しているコア」)ではなく、この
     * フィールド(=「このコネクションが実際に生成された/データを
     * 保持しているコア」)を使う -- job.cの共有スケジューラにより、
     * このconnを扱うjob stepが生成時と別のコアでtickされることがあり
     * うるため(netif_t.owner_coreと同じ設計方針)。
     * 【注意】これはあくまで「正しいスロットを見つけられる」ことだけを
     * 保証する -- 実際にNICハードウェア(eth.c/mlx5_net.c)へ送受信を
     * 発行する操作自体はコア間でスレッドセーフではないため、同じ
     * netif_tに属するjob群がowner_coreと異なるコアで*同時に*実行
     * されないことは、job.cのaffinity_key機構(job.h参照、nvmet.c/
     * nvme.cがbound_ctx/src_ctxをキーに設定する)側で別途保証する必要が
     * ある。 */
    volatile unsigned    owner_core;
} tcp_conn_t;

/* ts_log()のargへ渡す値を組み立てる: 上位8bit(bit31:24)=接続スロット
 * 番号(s_conns[]内でのconnのインデックス、接続確立時の起動ログ
 * "slot=%d"と同じ番号)、下位24bit=valueそのまま(tcp.cのtcp_conn_arg()
 * コメント参照)。元はtcp.c内のstatic関数だったが、nvme_tcp.c(2026-08-09、
 * コア0のSEND_H2C/RECV_CQE遅延解析向けに新設したNRFB/NRDNタグ)も同じ
 * エンコーディングでadmin/IO queueを区別する必要があり、複製を避けて
 * ここで公開した。 */
uint32_t tcp_conn_arg(const tcp_conn_t *conn, uint32_t value);

/* tcp_connect()を「SYN送信(ブロックしない)」と「ESTABLISHEDになる/
 * 再送/タイムアウトを1tick分だけ進める」の2段に分けたもの
 * (`tcp_accept_begin()`/`tcp_accept_ready_poll()`のconnect側対になる版、
 * NVMe/TCP制御のジョブ化、CLAUDE.md「NVMe/TCP制御のステートマシン化」
 * 節参照)。`tcp_connect()`は内部でこれらへ処理を委譲するだけ(外部から
 * 見た挙動は不変)。
 *
 * `tcp_connect_poll()`自体はtcp_poll_once()を呼ばない -- SYN-ACKの受信
 * 検出(`priv->ack_received`)やRST処理は`tcp_input()`が担い、それを
 * 実際に駆動するのは呼び出し側の外側にあるポーリングループ
 * (`net_poll_all_and_dispatch()`、通常はメインループが毎tick呼ぶもの)
 * に委ねる設計 -- `tcp_accept_ready_poll()`が`s_accept_ready`を確認
 * するだけで済むのと同じ理由。呼び出し側はタイムアウト管理をする
 * 必要は無い(再送上限到達で`tcp_connect_poll()`自身が-1を返す)。 */
void tcp_connect_begin(tcp_conn_t *conn, uint32_t dst_ip, uint16_t dst_port);

/* 戻り値: 1=ESTABLISHEDに到達(呼び出し側は次の処理へ進んでよい)、
 *         0=まだ(次tickにまた呼ぶ)、
 *         -1=失敗(送信失敗・再送上限到達・RST等・Ctrl+C中断。
 *             内部でs_conns[]のスロットを解放済みなので、呼び出し側が
 *             改めてtcp_close()を呼ぶ必要は無い) */
int  tcp_connect_poll(tcp_conn_t *conn);

/* ESTABLISHED(またはCLOSE_WAIT、半クローズ中)のconnへbuf/lenを送信する。
 * 輻輳ウィンドウ(cwnd)と相手の広告ウィンドウ(snd_win)の許す範囲で複数
 * セグメントをACKを待たずに連続送信し(パイプライン化)、累積ACKで
 * 一括して進める。RTOタイムアウト時は未確認区間全体を再送する
 * (Go-Back-N)。相手の広告ウィンドウが0の間は1バイトずつのプローブ送信
 * になる(RFC1122 persist相当の挙動が自然に生じる設計)。
 *
 * ゼロコピー送信: bufはコピーされず、RP1 GEMのDMAがbufのアドレスを
 * 直接読む(tcp_send_segment()参照)。このため呼び出し側は:
 *   (1) 少なくとも64バイト境界にアラインされたバッファを渡すこと
 *       (aligned(64) — net_buf_tと同じ制約。未アラインだとGEMのDMAが
 *       完了せずTXタイムアウトになる実機不具合を確認済み。原因は
 *       GEMのバースト転送のアライメント要求と推測されるが、正確な
 *       最小要求アライメントまでは特定していないため、確実に安全な
 *       net_buf_t相当の64バイトを推奨する)。
 *   (2) tcp_send()が返るまでbufの内容を変更しないこと(再送時に同じ
 *       bufを読み直すため)。
 * 戻り値: 送信できたバイト数(0<戻り値<=lenの部分送信もありうる)、
 *         1バイトも送れなかった場合は-1
 *
 * lenはuint32_t(2026-07-25、uint16_tから拡張): 内部のMSSセグメンテーション
 * ループは元々uint32_tで演算しており16bit化はこの引数の型だけが課す
 * 人為的な制限だった。この制限が原因で、呼び出し側(nvmet_tcp.cの
 * nvmet_tcp_send_c2h())がuint16_t上限を超えないよう1コマンド分のデータを
 * 32KB程度の複数チャンクへ分割し、チャンクごとに独立したtcp_send()呼び
 * 出し(=チャンクの最終バイトまで完全にACKされ切ってから次のチャンクの
 * 送信を開始する、という「完全ドレイン」の壁)を挟んでいた。1回の
 * tcp_send()呼び出し内では輻輳ウィンドウが許す限り複数セグメントを
 * 継続的にパイプライン送信できるのに対し、チャンク境界をまたぐたびに
 * このパイプラインを一度空にしてから最後のACKを待つという、実質的に
 * 送信のための待ち時間(概ね1RTT相当)が丸ごと無駄になる「パイプライン
 * バブル」が生じていた。読み出し(NVMe/TCP C2HData)の実効スループットが
 * 32KBチャンク固定のtcpbenchの実測値(約17.7〜17.9MB/s)と一致していた
 * のはこのため。lenをuint32_t化し1コマンド分(最大256KB、
 * nvmet.hのNVMET_MAX_TRANSFER_BYTES)を単一のtcp_send()呼び出しで送れる
 * ようにすることで、このチャンク境界のバブルを解消した
 * (nvmet_tcp.cのNVMET_TCP_C2H_CHUNK_MAX参照)。 */
int  tcp_send(tcp_conn_t *conn, const void *buf, uint32_t len);

/* tcp_send()と同じくESTABLISHED/CLOSE_WAITのconnへbuf/lenを送信するが、
 * 相手のACKを待たずに即座に返る(「送りっぱなし」版)。len は
 * TCP_ASYNC_MAX_LEN以下でなければならない(超える場合はtcp_send()に
 * フォールバックする、呼び出し元が複数回に分けて呼ぶこと)。
 *
 * 2026-08-10、LSO対応に伴い内部実装を拡張: len が conn->snd_mss を超える
 * 場合、従来は単純にtcp_send()(ブロッキング)へフォールバックしていたが、
 * 現在は接続先インターフェースのLSOケーパビリティ(netif_t.
 * hw_lso_max_bytes、conn->local_ipから解決)に応じて内部で自動的に
 * 使い分ける:
 * - LSO対応(ConnectX)かつlenがmssを超える: tcp_send_segment_lso()で
 *   1回のWQEとして丸ごとキューする(HWがmss単位に自動分割)。
 * - LSO非対応(RP1)、またはlenがmss以下: 従来通りtcp_send_segment()を
 *   mss単位で複数回呼び、それぞれ独立した非同期スロットとしてキューする
 *   (呼び出し元は1回のtcp_send_async()呼び出しで済むが、内部的には
 *   複数の未確認スロットを消費しうる)。
 * いずれの経路でもブロッキングtcp_send()へは(len>TCP_ASYNC_MAX_LENという
 * 契約違反の場合を除き)フォールバックしない — nvmet_tcp.cの
 * nvmet_tcp_send_c2h_async()/nvme.cのnvme_pipeline_h2c_pump()が、
 * mss単位の手動チャンク化を自前で行わず、TCP_ASYNC_MAX_LEN単位の大きい
 * チャンクをそのままこの関数へ渡せるようにするための変更(ロジックの
 * 重複を避け、将来の呼び出し元も自動的にLSOの恩恵を受けられる)。
 *
 * 2026-08-10、実機で発見した本物のバグの修正: 相手の広告ウィンドウ/
 * 輻輳ウィンドウ(tcp_send()のバーストループが使うusable_window=
 * min(snd_win,cwnd)と同じ計算)を、この関数も内部でチェックするように
 * なった。以前は無条件に送信していたため、受信側の処理が追いつかず
 * 実ウィンドウが縮小している状況でウィンドウ外のデータを送りつけ、
 * 相手がTCP仕様通り黙って破棄→再送も同じ理由で永久に失敗する
 * デッドロックを実機のNVMe/TCP write pipelineテストで確認した(24〜
 * 136バイトの小さいCQE/R2T/SQEしか送らなかった間は問題化しなかったが、
 * LSO対応で1回の送信を最大TCP_ASYNC_MAX_LENバイトまで拡大したことで
 * 顕在化した)。ウィンドウが埋まっている間はACK到達で自然に空くまで
 * (tcp_poll_once()を回すだけの)軽量な待ちが入る — 呼び出し元は依然
 * ブロッキングtcp_send()のような長時間ACK待ちには遭遇しない設計を
 * 維持している(健全な接続なら数十〜数百us程度で解決する)。
 *
 * 経緯: NVMe/TCPのWrite応答(CQE)送信でtcp_send()の「相手のACKが届くまで
 * ブロック」設計が、実機のWiresharkキャプチャで判明した以下の構造と
 * 悪い相互作用を起こしていた — ホストは次のコマンドを出す前にこちらの
 * CQEを待っており、こちらは(このCQE送信のために)ホストのTCP ACKを
 * 待っている。ホスト側に他に便乗させるデータが無いと、ホストの
 * TCP実装自身の遅延ACKタイマー(Linuxで標準的に約40ms)がこの単独ACKの
 * 送出を遅らせ、双方の待ち合わせにより1回のWriteコマンドあたり
 * 約40〜50msの停止が生じていた(CLAUDE.md参照)。データ自体はTCP自身の
 * 再送機構で確実に届くため、応答送信のたびに確認応答を同期的に待つ
 * 必然性は無い(eth_send_frags_async()がハードウェア送信完了を待たない
 * のと同じ考え方 — tcp.c冒頭のtcp_send_segment()コメント参照)。
 *
 * 信頼性: 送信直後は"未確認"として循環キュー(tcp_priv_tのasync_slots[]、
 * 最大TCP_ASYNC_SLOTS件、tcp.c参照)に積み、以後のtcp_poll_once()呼び出し
 * のたびに(このプロジェクトのあらゆる長時間ブロックする待ちループが
 * 経由する共通ポーリング関数、tcp_abort_requested()コメント参照)
 * バックグラウンドでACK到達を確認し、RTOを超えてもACKが届かなければ
 * そこで初めて再送する — 呼び出し元は一切ブロックされない。
 * TCP_MAX_RETRIES回再送してもACKされなければそのコネクションの未確認
 * キュー全体を諦めてログを出す(接続自体の生死判定は上位層のタイムアウト
 * に委ねる)。
 *
 * 呼び出し規則: 同一connで最大TCP_ASYNC_SLOTS件まで、前回分がACK未確認の
 * ままでも次のtcp_send_async()を呼べる(2026-07-25、1件だけの設計から
 * 拡張 -- 経緯は下記参照)。キューが満杯の状態で呼ぶと、内部で最低1件
 * 空くまでブロッキングで待ってから新しい送信を行う。また、いずれかの
 * tcp_send_async()がまだ未確認の間に同一connへtcp_send()を呼んでは
 * ならない(tcp_send()はpriv->snd_unaを呼び出し時点のconn->snd_seqへ
 * リセットするため、async送信分の「未確認」情報が失われる —
 * nvmet_tcp.cでの実際の使用パターン(応答送信の直後は必ず受信フェーズ)
 * ではこの制約に抵触しない)。
 *
 * 拡張の経緯(2026-07-25): 当初は1件だけしか同時にキューできない設計
 * だった(呼び出し元がCQE/R2Tのような「1件送ったら次は受信フェーズへ
 * 進む」単発応答専用に使う想定だったため)。しかしNVMe/TCPターゲット
 * (nvmet.c)がIOキューのパイプライン対応(複数の書き込みコマンドを
 * 同時にR2T応答待ちとして追跡)を実装したところ、同じコネクション上で
 * R2T/CQEを連続してtcp_send_async()する場面が増え、1件だけの追跡だと
 * 2件目以降が前の1件のACK確認を待ってブロックし、ホストの遅延ACK
 * タイマー(標準約40ms、上記「経緯」段落参照)を毎回踏んでIOPSが劣化する
 * 実機バグ(fio iodepth=2→4でスループットが約55MB/s→約17MB/sへ悪化)を
 * 確認した。TCPのACKは累積確認であることを利用し、循環キューの先頭
 * (最古)がACK済みになったかどうかだけを見る設計(tcp_send()のGo-Back-N
 * 再送と同じ考え方をこの小さい単発メッセージ集合に適用したもの)へ
 * 拡張して解決した。
 *
 * 戻り値: 成功時は実際にキューできたバイト数(>0、lenと一致するとは
 * 限らない — LSO非対応時にmss単位へ内部分割する過程で送信自体が失敗
 * すれば、それより前に成功した分だけを返す。呼び出し元は戻り値の分だけ
 * 前進し、残りを次回呼び出しで送ること) または -1(1バイトも送れなかった)
 *
 * 2026-08-11、len<=TCP_ASYNC_SHORT_MAX_LEN(512、tcp.c参照)のときは内部で
 * 完全に別の小さい専用キュー(tcp_priv_t.async_short_slots[])へ自動的に
 * 振り分ける -- CMD/RSP/R2T/ICResp等のヘッダ専用PDU(常にこの範囲に
 * 収まる)が、進行中の大きいH2CData/C2HDataチャンク送信(基礎の
 * TCP_ASYNC_SLOTS/mlx5オーバーフロープール側)と同じスロットを奪い合い、
 * H2C側がプールを埋め尽くしている間はCMD送信までブロックされる実機挙動を
 * 解消するため。呼び出し元(nvme_tcp_send_cmd_async()、nvmet_tcp_send_
 * icresp()/send_r2t()/send_resp()等)は一切変更不要 -- 振り分けは`len`の
 * 値だけで自動的に行われる。tcp_send_async_drain()は両キューが完全に
 * 空になるまで待つよう対応済み。 */
/* 2026-08-09、64→128へ拡張(ユーザー指示)。NVMe/TCPのCommand Capsule PDU
 * (`NVME_TCP_CMD_PDU_LEN`=72バイト、8ヘッダ+64 SQE)をtcp_send_async()
 * 経由で送れるようにするため(nvme_tcp.cのnvme_tcp_send_cmd_async()参照)。
 * 影響範囲はtcp_async_slot_t.bufのサイズ(tcp.c)のみで確認済み(このヘッダ/
 * tcp.c以外にTCP_ASYNC_MAX_LENへ依存するコードは無い、grepで確認済み)。
 *
 * 2026-08-09、さらに128→10182(tcp.cのTCP_MSS_LOCALと同値、変更する場合は
 * 両方揃えること)へ拡張(ユーザー指示 -- NVMe/TCP write負荷テストで
 * 実測した「H2CData送信のtcp_send()が、PDU末尾の未確認バイトのACKを
 * 待つだけで1コマンドあたり約1msの空費を生んでいた」問題への対応。
 * nvme.cのH2CDataパイプライン送信[nvme_pipeline_h2c_pump()参照]が、
 * 従来の1回のブロッキングtcp_send()(PDU全体を送り切りACKを待つまで
 * 戻らない)ではなく、MSS単位でtcp_send_async()を繰り返し呼ぶ設計に
 * 変更されたため、1回の呼び出しでMSS丸ごと(最大のジャンボMSS想定)を
 * キューできる必要がある)。
 *
 * 2026-08-10、さらに10182→32768(32KB)へ拡張(LSO対応 --
 * ~/.claude/plans/lexical-squishing-mitten.md参照)。nvmet_tcp_send_
 * c2h_async()/nvme_pipeline_h2c_pump()がmss単位の手動チャンク化を
 * やめ、この関数へ大きいチャンクをそのまま渡せるようにするため(上記
 * 関数コメント参照)。LSO自体のハードウェア上限(mlx5.hのMLX5_LSO_MAX_
 * BYTES_CAP=65536、tcp.cのTCP_LSO_MAX_DATA_LEN=65495)より小さい値を
 * あえて選んでいる — TCP_ASYNC_MAX_LENはtcp_async_slot_t.bufという
 * 「TCP_ASYNC_SLOTS×TCP_MAX_CONNS×SMP_MAX_CORES」全通り分の固定バッファ
 * (NVMET_MAX_PENDING_WRITES(8)×2に合わせたTCP_ASYNC_SLOTS=16件、
 * 小さいCQE/R2T/SQEヘッダ用にも共用)として静的確保されるため、
 * 65495まで引き上げると16×12×2×(65495-10182)≈21.2MBもの.bss増加になり、
 * 実機ビルドで`.dma_bss`(固定物理アドレス、mlx5専用DMA領域)と
 * オーバーラップしてリンクエラーになることを確認した(実測)。32768なら
 * 増分は16×12×2×(32768-10182)≈8.3MBに収まり、MSS単位(約9938B)の
 * チャンクに対して依然として約3.3倍のチャンク集約効果があるため採用。
 * TCP_ASYNC_SLOTSは変更しない(NVMe/TCP write pipeline depth=8との
 * 対応関係、tcp.cのTCP_ASYNC_SLOTSコメント参照 -- 減らすと書き込み
 * パイプラインのCQE/R2T送信が部分的にブロックされる退行を招く)。 */
#define TCP_ASYNC_MAX_LEN 32768u
int  tcp_send_async(tcp_conn_t *conn, const void *buf, uint16_t len);

/* 2026-08-15、ゼロコピー版。tcp_send_async()と全く同じ規約だが、送信元bufを
 * 内部スロットへコピーせずポインタ参照だけを保持する(再送も同じポインタから
 * 行う)。256KB級のC2HData read送信でコピー由来のメモリ帯域(100GbEで律速)を
 * 丸ごと省くのが目的。【必須の呼び出し規則】このconnで当該async送信がACK
 * されるまで、呼び出し元はbufの内容を変更・解放してはならない。安定した
 * バッキングストア(nvmetのram_disk等、送信完了までデータが不変)を送信元と
 * する用途に限る。それ以外(スタック上の一時バッファ等、送信後すぐ内容が
 * 変わりうるもの)は必ずコピー版tcp_send_async()を使うこと。 */
int  tcp_send_async_ref(tcp_conn_t *conn, const void *buf, uint16_t len);

/* データ受信、または相手からのFIN受信(半クローズ、CLOSE_WAITへの遷移)を
 * 最大timeout_msだけ待つ。
 * 戻り値: >0=受信したバイト数、
 *         0=相手の送信方向が閉じた(CLOSE_WAITに入った。コネクション自体は
 *           まだ生きており、必要ならこの後もtcp_send()できる。送信も
 *           終わったらtcp_close()を呼ぶこと)、
 *         -1=タイムアウト
 *
 * maxlenはuint32_t(2026-08-08、uint16_tから拡張): tcp_send()のlen引数を
 * uint32_t化した際と同じ理由 -- 内部実装(tcp_recv_internal())はrx_count
 * (uint32_t、TCP_RX_BUF_SIZE=512KBに対応)を扱えるのに、呼び出し側APIの
 * maxlenだけがuint16_tのまま残っていた。これが原因で、65536バイト以上の
 * 一括受信を試みる呼び出し元(呼び出し時にmaxlen自体が下位16bitへ暗黙
 * truncateされる、65536の倍数だとmaxlen=0になり無音のバグになる)が
 * 大きな転送を正しく行えなかった(test.cのTCP_TEST_MAX_LEN拡張時に発覚)。 */
int  tcp_recv(tcp_conn_t *conn, void *buf, uint32_t maxlen, uint32_t timeout_ms);

/* tcp_recv()と同じだが、読み取り後の明示的なwindow更新ACKを送らない版。
 * 呼び出し元が既知の合計長を複数回の呼び出しで蓄積し、蓄積完了後すぐに
 * 何らかの応答(その時点の空き容量を反映した新しいwindowを自然に運ぶ)を
 * 送ることが分かっている場合にのみ使うこと -- そうでない用途で使うと
 * 相手が長時間window更新を受け取れず、バッファがほぼ埋まっていた場合に
 * 送信を再開できなくなる恐れがある(nvmet_tcp.cのnvmet_tcp_recv_exact()
 * 参照、TCP_RX_BUF_SIZEに対して十分小さい1コマンド分のデータを蓄積後
 * 即座にCQE/C2HDataを返す用途向け)。maxlenがuint32_tである理由はtcp_recv()
 * と同じ。 */
int  tcp_recv_no_ack(tcp_conn_t *conn, void *buf, uint32_t maxlen, uint32_t timeout_ms);

/* ================================================================
 * 受信upcall(inline receive、二重コピー削減の基盤、2026-08-13)
 *
 * 従来のTCP受信は「tcp_input()がin-orderデータをper-connectionのrx_buf
 * (ソケットバッファ相当)へ積む(copy2)→上位層(ULP)が別ステップで
 * rx_bufをdrainして解釈(copy3)」という2段構成で、これが二重コピーの
 * 原因だった。ULPは受信先(NVMe/TCPならram_disk[slba])をSQEをパースする
 * まで知り得ないが、そのSQEはstreamの中にあるため、net_pollがコマンド
 * 全体をrx_bufへ積んでからでないとULPが動けず、直接配置の機会を逃す。
 *
 * 受信upcallは、このlayeringを融合する: コネクションにupcallを登録すると、
 * tcp_input()はin-orderデータをrx_bufへ積む代わりに *その場で*
 * upcall(ctx, data, len)を呼ぶ。ULPは渡されたバイト列をストリームとして
 * パースしながら、ヘッダ/SQEは小さな内部バッファへ、bulkデータは最終
 * バッファ(ram_disk等)へ直接コピーできる -- rx_bufステージングも別ジョブ
 * のdrainも無く、ネットワークから最終バッファまで1コピーで済む。
 * SQEをパースした「その場で」以降のバイトの宛先を切り替えられるため、
 * 同一net_pollバッチ内の後続データも直接配置できる(pull型では不可能
 * だったタイミング問題を解消する)。
 *
 * upcallは渡された全lenバイトを同期的に消費すること(内部バッファ/最終
 * バッファへコピーする、決してブロックしない)。dataは受信バッファ由来の
 * volatileポインタで、呼び出し中のみ有効。100Gbps級への移植でもこの
 * inline receiveが無駄コピー削減の基盤になる。 */
/* [関数ポインタ登録先 -- ctagsジャンプ補助] tcp_set_recv_upcall()で登録される具体関数:
 *   nvmet_io_rx_upcall(nvmet.c)  : target のH2CData受信(push型write受信)
 *   nvme_read_rx_upcall(nvme.c)  : initiator のC2HData受信(push型read受信)
 * 間接呼び出しは tcp.c の tcp_deliver_data() 内 priv->recv_upcall(...)。 */
typedef void (*tcp_recv_upcall_fn)(void *ctx, const volatile uint8_t *data, uint16_t len);

void tcp_set_recv_upcall(tcp_conn_t *conn, tcp_recv_upcall_fn fn, void *ctx);
void tcp_clear_recv_upcall(tcp_conn_t *conn);

/* pull型二重コピー時間計測(push vs pull 比較、検証後に撤去)。 */
void tcp_copy_stats_get(uint64_t *c2_ns, uint64_t *c2_by,
                        uint64_t *c3_ns, uint64_t *c3_by);

/* クローズシーケンスを開始する。conn->stateに応じて2通り:
 *   - ESTABLISHED(能動close): FINを送りFIN_WAIT_1へ。相手のACKとFINを
 *     待ってTIME_WAIT相当まで進める。
 *   - CLOSE_WAIT(受動close、相手が先にFIN済み): FINを送りLAST_ACKへ。
 *     相手のACKを待つ。
 * いずれも2MSL待ちは省略する(本実装はNVMe/TCP検証用の最小限クライアント
 * であり、TIME_WAIT明けを待たず即座にconn->stateをCLOSEDへ落とす)。
 * それ以外の状態(既にCLOSED等)なら何もしない。 */
void tcp_close(tcp_conn_t *conn);

/* ip.cから呼ばれる受信ハンドラ。現在アクティブな全conn(tcp_connect()が
 * 登録した最大TCP_MAX_CONNS本、tcp.c参照)のport/IPと照合し、一致した
 * ものにディスパッチする(一致するconnが無ければ無視)。
 * pkt/len: TCPヘッダ+データ(IPペイロード全体)
 * src_ip:  送信元IPv4アドレス(ホストバイトオーダー) */
void tcp_input(const uint8_t *pkt, uint16_t len, uint32_t src_ip);

/* 同時に待ち受けられるリスナー(tcp_listen()ハンドル)の最大数。nvmet常駐
 * サーバ最大3系統(RP1+ConnectX PF0/PF1、platform_init.c参照。各インス
 * タンスがadmin/IO両方のaccept段階で1個のリスナーを使い回す、CLAUDE.md
 * 「nvmet: 複数インターフェース同時待受」節参照)で3個、telnetで1個、
 * ftpd(ftpd.c、LAN fwupdate)が制御+データの2個を常時占有しうる(計6個)
 * 前提で、手動`nvmet`コマンド/iperf3/testの自己完結テスト等の一時的な
 * 用途にも余裕を残して8にしてある。 */
#define TCP_MAX_LISTENERS 8u

/* ポートをリッスン登録する。実際の受動acceptはtcp_accept()/
 * tcp_accept_begin()+tcp_accept_wait()が行う -- これはディスパッチ対象の
 * ポート番号(と、下記ctx)を覚えるだけ。
 *
 * ctx: このリスナーが受け付けるSYNを、特定のネットワークインターフェース
 * (netif.hのnetif_t、`net init mlx5`のConnectX PF0/PF1等)からのものに
 * 限定したい場合に渡す。net_poll_all_and_dispatch()(netif.c)は登録済みの
 * 全インターフェースを順にg_active_ctxとしてactivateしてからpoll_recv()/
 * eth_dispatch()するため、tcp_input()がこのSYNを処理する時点のg_active_ctx
 * は「実際にこのフレームを受信したインターフェース」と一致する。ctxを
 * 渡すと、tcp_input()はg_active_ctx==ctxのSYNのみをこのリスナーに一致
 * させる -- 複数のリスナーが同じport番号で異なるインターフェースへそれぞれ
 * 独立にbindできるようにするため(nvmetの3系統同時待受で必須。3系統とも
 * 同じport=4420を使うが、RP1宛のSYNはRP1用リスナーへ、ConnectX PF0宛の
 * SYNはPF0用リスナーへ、という具合に正しく振り分ける必要がある)。
 * NULLを渡すと、従来通りインターフェースを問わず(port一致のみで)受け
 * 付ける -- iperf3.c/test.c等、単一インターフェース運用を前提とする既存
 * 呼び出し元向けの後方互換動作。
 * 戻り値: リスナーハンドル(0以上、以後のtcp_accept系関数やtcp_unlisten()
 *         へ渡す)、失敗時-1(TCP_MAX_LISTENERS個のスロットが全て使用中)。 */
int tcp_listen(uint16_t port, netif_t *ctx);

/* tcp_accept()を「受け付け準備(ブロックしない)」と「ESTABLISHEDになる
 * のを待つ(ポーリングループ)」の2段に分けたもの。tcp_accept()は
 * 内部でtcp_accept_begin()に続けてtcp_accept_wait()を呼ぶだけ
 * (実装は同じ)。
 *
 * これが必要な理由(実機のnvmet実装で発見): admin queueの最後の応答
 * (Set Features(Number of Queues)のCQE)をtcp_send()で送信している間、
 * 相手は(こちらの応答を待たず)ほぼ同時にIO queue用の新規SYNを送って
 * くることがある。従来通りadminの応答を送り終えてからtcp_accept()を
 * 呼ぶ設計だと、この早着SYNが届いた時点ではまだ受け皿が用意されておらず、
 * そのSYNは黙って捨てられる(アクティブなconnにも一致せず、受け付け中
 * でもないため)。相手のSYN再送(通常1秒程度後)で最終的には救われるものの、
 * 実機のnvme-tcpホストではこの遅延が全体のキュー確立タイムアウトに
 * 食い込み、IO queueのICReq/ICResp成功直後に接続ごと中断される事象を
 * 確認した。呼び出し側(nvmet.c)は、adminの最後の応答を送るより前の
 * 早い段階でtcp_accept_begin()を呼んで受け皿を用意しておき、応答送信後に
 * tcp_accept_wait()で実際にESTABLISHEDになるのを待つことで、この
 * 早着SYNを最初の到着で取りこぼさずに済む。 */
void tcp_accept_begin(int listener, tcp_conn_t *conn);

/* tcp_accept_wait()の非ブロッキング版(NVMe/TCP制御のジョブ化、CLAUDE.md
 * 「NVMe/TCP制御のステートマシン化」節参照)。tcp_accept_wait()はwhile
 * ループ(do-whileではない)のため、timeout_ms=0で呼んでも本体
 * (tcp_poll_once()+確認)を一度も実行せず受け皿をリセットして
 * 即座に-1を返してしまい、ジョブの1tick分の非ブロッキング試行としては
 * 使えない -- そのwhileループの中身を1回分だけ切り出したもの。
 * tcp_accept_begin()で受け皿を用意した後、この関数を毎tick呼んで
 * ESTABLISHEDになるのを待つこと(タイムアウト管理は呼び出し側が行う --
 * この関数自体はタイムアウトしない)。
 * 戻り値: 1=ESTABLISHEDに到達(受け皿は消費済み)、0=まだ */
int  tcp_accept_ready_poll(int listener);

/* リッスンを解除し、listenerスロットを解放する(以後別の用途で再利用
 * できる)。 */
void tcp_unlisten(int listener);

/* connでWindow Scaling(RFC7323、tcp.h冒頭コメント参照)が成立している
 * かどうかを返す(1=成立、0=不成立または未登録のconn)。上位層
 * (nvmet_tcp.c)が、大きな単発PDU(R2T+H2CData等)を安全に1ラウンドで
 * 送受信できるか(こちらの広告ウィンドウが65535を超えられるか)を
 * 判断するために使う -- 成立していない接続に65535を超えるPDUを
 * 前提とした設計を適用すると、こちらのウィンドウ更新ACKが届かない
 * ままホストが永久に待たされるデッドロックを招く(2026-07-25、
 * 256KB R2T対応の検討中に発見)。 */
int tcp_window_scaling_enabled(const tcp_conn_t *conn);

/* デバッグ用: connのTCP受信状態(state/seq/window/rx_read/rx_count/
 * Window Scaling状態/OOOスロット)と、rx_buf周辺(直前に読んだ位置の
 * 少し前から)の生バイトをhexdumpしてUARTへ出力する。rx_bufの実アドレス
 * も表示するので、呼び出し元がセッションを終了した後にシェルの`md`
 * コマンドでさらに広い範囲を確認することもできる。
 * 2026-07-25、256KBの単発R2T+H2CData受信で発生したストリームdesync
 * バグの調査用に追加した一時的な診断コード -- 原因特定後は削除を
 * 検討すること。 */
void tcp_debug_dump_rx(const tcp_conn_t *conn);

#endif /* TCP_H */
