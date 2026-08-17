# プロトコル未実装項目の実装計画

このリポジトリの TCP/IP・NVMe-oF スタックで「本来サポートすべきだが未実装」の
項目を、着手順に並べた計画書。**セッションをまたいで引き継ぐためのもの**なので、
各項目に「なぜ要るか / どこを触るか / どう検証するか / この環境固有の落とし穴」を
書いてある。

実装順は **C1/C2 → E → D1 → A1〜A6 → B系**(ユーザ指定)。

## 進捗

| 段階 | 項目 | 状態 |
|---|---|---|
| 1 | C1 TCP RST 送信 | **完了**(実機確認済み 2026-08-16) |
| 2 | C2 高速再送/高速回復 | **完了**(実機確認済み 2026-08-16) |
| 3 | E RDMA リソース解放 | **完了**(実機確認済み 2026-08-16) |
| 4 | D1 NVMe-oF Discovery サービス | **完了**(実機確認済み 2026-08-16) |
| 5 | A1 ルーティング/ゲートウェイ | **完了**(実機確認済み 2026-08-17) |
| 6 | A2 ARP/NDP キャッシュのエージング | 未着手 |
| 7 | A3 重複アドレス検出(ARP Probe / IPv6 DAD) | 未着手 |
| 8 | A4 送信側 IP フラグメント | 未着手 |
| 9 | A5 ICMP Time Exceeded / Frag Needed | 未着手 |
| 10 | A6 ICMPv6 Packet Too Big + PMTUD | 未着手 |
| 11 | B1 RS/RA + SLAAC | 未着手 |
| 12 | B2 MLD | 未着手 |
| 13 | B3 NUD | 未着手 |
| 14 | B4 IPv6 拡張ヘッダ/フラグメント | 未着手 |

**着手したらこの表を更新すること。** 実機で確認できていないものを「完了」に
しない(このプロジェクトの一貫した方針)。

---

## 全項目に共通する作業ルール

- **編集は Windows 側 `C:\Users\fukud\Documents\vfio_nvme` が正。** OptiPlex の
  `~/vfio_nvme` は `--delete` 付き rsync で上書きされる。詳細は `CLAUDE.md`。
- **仕様は推測せず実ソースを取得して確認する。** Linux カーネル
  (`torvalds/linux`)や `linux-rdma/rdma-core` を実際に取ってきて、構造体の
  バイトオフセットとフィールド値を突き合わせる。GitHub の raw が 429 を返す
  ときは `git clone --filter=blob:none --no-checkout --depth=1` +
  `git sparse-checkout` で回避できる(実績あり)。
- **性能に触る変更は同一セッション内で HEAD と A/B する。** この環境は
  実行ごとに 4〜20% ばらつく。単発比較で結論を出さない。`git stash -u` で
  HEAD を測り、`git stash pop` で戻すのが確実。
- **5% 以上の性能変化があったら `CLAUDE.md` の性能表を更新する。**
- 実機テストは常駐シェルの中で行う。単発プロセスの起動を繰り返すと
  ConnectX/ホストが wedge する(電源断が要る)。

### 既存の検証コマンド

| コマンド | 用途 |
|---|---|
| `tcpbench [KB[,KB..]] [r\|w\|rw] [qd] [hdgst] [ddgst] [ipv6]` | NVMe/TCP スループット |
| `bench [KB[,KB..]] [r\|w\|rw] [qd]` | NVMe-oF RDMA スループット |
| `tcp6test` | IPv6 上で TCP 確立 + 64KB 往復のバイト一致 |
| `udptest` / `udptest6` | UDP 往復(v4 は Port Unreachable も確認) |
| `ping6` | ICMPv6 Echo 往復 |
| `rsttest` | 待ち受け無しポートへ v4/v6 で接続し RST で即失敗するか |
| `txdrop [N]` | ロス注入(データ N 個に 1 個破棄、0=無効)+ 再送統計 |
| `qploop [N]` | RC QP の作成/破棄を N 回繰り返し FW リソースの枯渇を見る |
| `nvmediscover [dump]` | Discovery Log Page を取得(`dump` で 16 進出力)|
| `route [<if> <netmask> <gw>]` | 経路の表示/設定(`gw` に 0.0.0.0 で解除)|
| `routetest` | サブネット外宛がゲートウェイの MAC で送られるか(v4/v6)|
| `ts mask <mask> <value>` | ts_log の絞り込みダンプ(タグは File#\|Func#\|info) |
| `monitor` / `err` | HW 状態・エラーカウンタ |

---

# 段階 1: C1 — 閉じたポートへの SYN に RST を返す 【完了】

## 実装結果(2026-08-16)

計画どおり `tcp_send_bare_ack()` を `tcp_send_bare(..., flags, seq, ack)` へ
一般化し、`tcp_send_bare_ack()` / `tcp_send_bare_rst()` をその薄いラッパにした。
`tcp_input_addr()` の「どのコネクションにも一致しない」経路で RST を返す。

**計画に無かったが必要だった判断が 2 つある**(どちらも入れないと退行する):

1. **リスナが居るポートには RST を返さない。** 受動 open のマッチ条件は
   「`accept_conn` が用意済みでかつ `TCP_CLOSED`」なので、accept を張り直す
   一瞬の隙間(`nvmet` が admin キュー確立後に IO キューの accept を arm する
   までの間、`nvmet.c` の `NIO_ST_WAIT_ADMIN_READY` → `NIO_ST_ARM`)に届いた
   SYN が「閉じたポート宛」に見える。ここで RST を返すと、**イニシエータの
   IO キュー接続が即座に失敗する**。`tcp_port_has_listener()` で
   「ポートが開いているか」だけを見て、armed でないなら黙って捨てて相手の
   SYN 再送に任せる(Linux が accept キュー溢れで落とすのと同じ扱い。
   C5「listen backlog」を入れるときはここを見直す)。
2. **TIME_WAIT の照合を FIN 限定から 4-tuple 一致だけに広げた。** 元の実装は
   「FIN が立っているときだけ」TIME_WAIT テーブルを引いていた。RST を足すと、
   閉じた直後の相手から届く FIN 以外の遅延セグメント(重複 ACK など)が
   「閉じたポート宛」と判定され、**相手の TIME_WAIT を RST で勝手に潰す**。
   一致したら FIN のときだけ ACK を返し、それ以外は黙って捨てる。

保険として `tcp_conn_exists_any_core()`(全コアのスロットを走査)を RST 直前に
挟んである。受信ホットパスの照合は自コアぶんしか見ないので、将来
`smp_boot_core2/3` を有効にして受信を複数コアへ振ったときに
**自分のコネクションを自分で撃つ**のを防ぐ。冷たい経路なので性能への影響は無い。
宛先が IPv6 マルチキャストのときも返さない。

## 実機での確認結果

| 確認項目 | 結果 |
|---|---|
| `rsttest`(v4/v6、3 回) | **PASS**。失敗確定まで 134〜191us(RST 無しなら SYN 再送 5 回で 15.5 秒) |
| `bench 8,64,256 rw 8`(RDMA) | 退行なし。**ログに RST は 1 行も出ない**(懸念していた RoCEv2 複製フレームの影響は無し) |
| `tcpbench 8,64,256 rw 8` | 退行なし(下表)。admin/IO 両キューの accept が RST に潰されないことも確認 |
| `tcp6test` / `ping6` / `udptest` / `udptest6` | すべて PASS |

測定値(括弧内は `CLAUDE.md` の基準値。いずれも測定ばらつきの範囲):

| | RDMA | TCP |
|---|---|---|
| write 8k | 4128 (4310) | 840 (856) |
| write 64k | 5838 (5803) | 3164 (3309) |
| write 256k | 5999 (5787) | 3980 (3968) |
| read 8k | 4340 (4373) | 2331 (2334) |
| read 64k | 6717 (6813) | 5022 (5024) |
| read 256k | 6071 (6070) | 5266 (5242) |

## 現状(着手前)

`tcp.c` の `tcp_input_addr()` は、どのコネクションにもリスナにも一致しない
セグメントを**黙って捨てている**(`return; /* どのアクティブコネクション宛でも
ない */`、2440 行付近)。`TCP_FLAG_RST` はファイル中 1 箇所にしか現れず、
**送信経路が存在しない**。

## なぜ要るか

相手は接続失敗を即座に知れず、SYN 再送のタイムアウト(数秒〜十数秒)まで
待たされる。ポートスキャンや誤設定の切り分けも困難になる。テスト自動化で
「ターゲット未起動」を素早く検出できないのは実害。

## 設計

`tcp_send_bare_ack()` が既に「登録済みコネクションを持たない相手へ単発の
セグメントを送る」最小構成になっている。**これを一般化するのが最小変更**:

```c
/* seq/ack とフラグを引数化する。ACK/RST どちらも同じ経路で送れる。 */
static void tcp_send_bare(const netaddr_t *local_ip, uint16_t local_port,
                          const netaddr_t *remote_ip, uint16_t remote_port,
                          uint8_t flags, uint32_t seq, uint32_t ack);
```

`tcp_input_addr()` の「一致しない」経路で、RFC 793 の規則に従って返す:

- 受信セグメントに **RST が立っていれば何も返さない**(RST に RST を返して
  無限ループにしない。これが最重要)。
- 受信に ACK が無い → `seq=0, ack=SEG.SEQ+SEG.LEN(+SYN/FIN 分), RST|ACK`
- 受信に ACK がある → `seq=SEG.ACK, ack=0, RST`

`local_ip` は `dst`(NULL なら `netaddr_v4(NET_SELF_IP)`)、`remote_ip` は `src`。
v4/v6 は既に `tcp_build_l3()` が吸収するので family 分岐は不要。

## 落とし穴

- **RoCEv2 の複製フレームに注意。** RoCEv2 のフレームは catch-all フロー
  ステアリング経由で Ethernet RX にも複製されて来る。UDP を実装したとき、
  これに ICMP Port Unreachable を返して自分の RDMA トラフィック 1 パケット
  ごとにエラーを撒き散らした前例がある(`ip.c` で UDP 4791 を除外して解決)。
  **TCP では同じ問題は起きないはず**(複製されるのは UDP/4791 だけ)だが、
  実装後に `bench`(RDMA)を回してログに RST が出ないことを必ず確認する。
- TIME_WAIT テーブルに一致するものは既に ACK を返す経路がある。**その判定より
  後ろに RST 送信を置く**(順序を逆にすると TIME_WAIT 中の再送 FIN に RST を
  返してしまう)。

## 検証

1. `tcpbench` / `bench` / `tcp6test` が退行しないこと。
2. 待ち受けの無いポートへ接続して即座に失敗すること。`tcp6test` の port を
   listener 未起動の番号に変える一時テスト、または新規に
   「存在しないポートへ `tcp_connect_begin` して `tcp_connect_poll` が
   即 -1 を返す」ことを見る小さなシェルコマンドを足す。
3. `bench`(RDMA)実行中に RST が飛んでいないこと(上記の落とし穴)。

---

# 段階 2: C2 — 高速再送 / 高速回復(dup ACK)【完了】

## 実装結果(2026-08-16)

検出は `tcp_input_addr()`、再送は既存の再送経路(`tcp_send()` の Go-Back-N
ループ / `tcp_async_poll()` / `tcp_async_short_poll()`)が担う、という計画どおりの
分担にした。ロス注入用に `txdrop <N>` シェルコマンドを追加(**恒久的に残す**。
DAC 直結ではロスが起きないので、これが無いと二度と検証できない)。

**計画の想定と違って、実装の 8 割は「ループバックで誤検出しないようにする」
作業だった。** 素直に RFC 5681 を書くと、このスタックでは検出が発散する。
以下の 4 つはいずれも実機で数値を見て初めて分かったもので、順に潰していった。

### 1. ウィンドウ更新 ACK が重複 ACK と見分けられない(最大の問題)

`tcp_recv_internal()` はアプリが受信バッファを読み出すたびに純 ACK を送るが、
このスタックの広告ウィンドウは `safe_window_cap` で頭打ちなので、バッファが
どれだけ空いても**ワイヤ上の値が動かない**。結果「ack 据え置き・データ無し・
ウィンドウ不変」となり、RFC 5681 の重複 ACK の定義に完全一致する。
**ロスが 1 つも無いのに重複 ACK を 419 万個検出し、高速再送が 10 万回空振り
していた。**

対策は送信側ではなく受信側:「ACK 番号もウィンドウも前回広告した値と同じなら
そもそも送らない」(`tcp_send_window_update()`)。相手に伝える情報がゼロなので
情報の損失は無い。**これで誤検出が完全に 0 になり、副次的に write 8k が
856 -> 1025 MB/s(+20%)へ上がった**(無駄な ACK 送信ぶんの CPU と帯域が浮いた)。
read が変わらないのは、read の受信側が push 型 upcall で `rx_buf` を経由せず、
そもそもこの経路を通らないため。

### 2. 高速再送は 1 セグメントではなく Go-Back-N にする

RFC 5681 どおり「穴の先頭 1 セグメントだけ」を送り直す実装から始めたが、
この受信側は順序不正セグメントを 64 スロットしか保持できず(`TCP_OOO_SLOTS`)、
未確認ウィンドウはそれよりずっと大きい。1 セグメントずつ埋めると先読み
バッファが溢れて二次的な穴が増え、**ロス注入時のスループットが 8.99 MB/s まで
落ちた**。RTO 経路と同じ Go-Back-N に変えたら 736 MB/s(**82 倍**)。
**受信側の能力に送信側の再送戦略を合わせる**、という判断。

### 3. Go-Back-N が生む重複 ACK を差し引く(`dup_ack_suppress`)

Go-Back-N で K セグメント送り直すと、その大半は相手が既に持っている。
この受信側は「in-order で受理できなかったセグメント」に即座に ACK を返すので、
**K 個送り直せばほぼ K 個の重複 ACK が返る**。K>=3 ならそれだけで次の高速再送の
条件を満たし、再送 -> 重複 ACK -> 再送 の正のフィードバックになる
(破棄 1318 個に対し再送 517527 回)。送り直したセグメント数を数え、その分の
重複 ACK は損失の証拠として数えない。RTO 経路の Go-Back-N にも同じ処理を入れた。

### 4. NewReno の partial ACK 再送は入れない

「partial ACK のたびに次のセグメントを再送」は Go-Back-N と組み合わせると
再送が爆発する(破棄 71 個に対し再送 3184 回)。`recover` は
**回復中に新しい回復を始めないためのガード**としてだけ使い、partial ACK での
再送はしない。穴が 2 つ以上あるときは次の 3 dup ACK か RTO が拾う。

## 実機での確認結果

| 確認項目 | 結果 |
|---|---|
| `txdrop 5000` + `tcpbench` | 破棄 540 に対し再送 1417。**うち高速再送 1379 / RTO 由来 38** — 97% が RTO を待たずに回復 |
| `txdrop 10` + `tcp6test` ×5 | 全て **PASS(64KB バイト一致)**。データ整合性はロス下でも維持 |
| ロス無し(`txdrop 0`)| **重複ACK=0 / 再送=0**。誤検出なし |
| `bench`(RDMA) | 無影響(tcp.c を通らない)。4305/5796/5997/4376/6807/6055 |
| 無ロス性能 | 下表。**write 8k が +20%**、他は測定ばらつきの範囲 |

無ロス時の `tcpbench 8,64,256 rw 8`(連続 2 回):

| | 1 回目 | 2 回目 | 従来値 |
|---|---|---|---|
| write 8k | 1050.9 | 1001.0 | 856 |
| write 64k | 3347.6 | 3489.0 | 3309 |
| write 256k | 4060.4 | 4054.0 | 3968 |
| read 8k | 2307.8 | 2305.0 | 2334 |
| read 64k | 5036.4 | 5057.1 | 5024 |
| read 256k | 5257.4 | 5262.3 | 5242 |

## 残っている限界(意図的に直していない)

- **`tcp6test` 程度の小さい転送では高速再送が発火しない。** 64KB=8 セグメント
  では 3 個の重複 ACK が溜まる前に転送が終わり、RTO 経路が拾う(`txdrop 10` で
  破棄 5・高速再送 0・RTO 由来 16)。これは正常。
- **ロス下の絶対スループットは落ちる**(1/5000 で read 8k が 2308 -> 323)。
  1 コマンド 3.3us の小 I/O にとって RTT スケールの回復でも十分重い。
  RTO(200ms)で回復していた従来よりは桁違いに良い、という位置づけ。
- SACK が無いので Go-Back-N から抜けられない。C3(SACK)を入れれば 2. と 3. の
  問題は根本的に消える。

## 着手前の現状

`tcp_priv_t` に `cwnd` / `ssthresh` / `snd_una` / `rto_ms` はあるが、
**重複 ACK のカウンタが無い**(`dup_ack` という識別子がコード中に存在しない)。
ロス検出は RTO 頼りで、1 パケット落ちるたびに最低 `TCP_RTO_MIN_MS` 停止する。

## なぜ要るか

- **性能測定の再現性に直結する。** 現在の測定ばらつき(同一バイナリで 4〜20%)の
  一因がこれ。1 パケットのロスが数百 ms の谷を作る。
- `ssthresh` は初期値 `0xFFFFFFFF` のまま実質無制限で、輻輳回避フェーズへ
  入る契機が RTO しかない。

## 設計(RFC 5681 の Fast Retransmit / Fast Recovery)

`tcp_priv_t` に追加:

```c
uint32_t dup_ack_count;   /* 同一 ACK 番号の連続受信数 */
uint32_t last_ack_seen;   /* 直前に見た ACK 番号 */
uint32_t recover;         /* Fast Recovery 中の目標 seq(NewReno) */
int      in_fast_recovery;
```

`tcp_input_addr()` の ACK 処理:

1. `ack == last_ack_seen` かつ新規データ無し・ウィンドウ更新無し → `dup_ack_count++`
2. `dup_ack_count == 3` → **高速再送**: `ssthresh = max(cwnd/2, 2*MSS)`,
   `cwnd = ssthresh + 3*MSS`, `snd_una` から 1 セグメント再送, `in_fast_recovery=1`,
   `recover = snd_seq`(送信済みの最大 seq)
3. Fast Recovery 中の追加 dup ACK → `cwnd += MSS`(ウィンドウ膨張)
4. 新しい ACK が来たら → `cwnd = ssthresh`, `in_fast_recovery=0`, カウンタリセット
   (NewReno の partial ACK 対応まで入れるかは実装時に判断。まず全 ACK で
   抜ける単純版で良い)

再送そのものは既存の RTO 再送経路(`tcp_send()` の再送ループ、
`tcp_async_poll()` の `ARTX`)を再利用する。**新しい再送機構を作らない**こと。

## 落とし穴

- **`tcp_send()` は同期ブロッキングのバルク送信ループを持ち、`tcp_send_async()`
  は別の非同期スロット機構を持つ。** dup ACK の検出は `tcp_input_addr()` 側で
  行うが、実際に再送する主体が 2 系統あるので、どちらに効かせるかを最初に
  決めること。NVMe/TCP の実データは主に `tcp_send()`(C2HData/H2CData)と
  `tcp_send_async()`(CQE/R2T)を通る。
- **遅延 ACK と相互作用する。** こちらは「フルサイズ 2 個に 1 回 ACK」なので、
  相手から見た dup ACK の出方が標準的な実装と違う。自作 initiator ↔ 自作
  target だけで試すと**両側が同じ癖を持つため検出できない穴**がある
  (CRC32C で実際に踏んだ)。可能なら Linux の nvme-tcp を相手にした
  `~/script/linux_loopback.sh` でも確認する。
- ループバック直結ではそもそもパケットロスがほぼ起きない。**人為的にロスを
  作る手段が要る**(例: `tcp_send_segment()` に「N 回に 1 回だけ送信を捨てる」
  デバッグフラグを一時的に入れる。使用後に削除する)。

## 検証

1. ロス注入フラグを入れて、RTO ではなく 3 dup ACK で再送されることを
   `ts mask`(File#=tcp.c)のトレースで確認する。
2. ロス注入を外し、`tcpbench 8,64,256 rw 8` を**複数回**実行してばらつきが
   縮むかを見る。縮まなくても正しさが確認できていれば採用してよい
   (ループバックではロスが無いので効果が出ないのは想定内)。
3. RDMA(`bench`)は tcp.c を通らないので無影響のはず。ドリフト確認用の
   対照として一緒に測る。

---

# 段階 3: E — RDMA リソースの解放 【完了】

## 実装結果(2026-08-16)

`mlx5_qp_destroy()` を「QP に付随する資源も含めて全部返す」形へ拡張した。
呼び出し元(`nvmer_destroy_qp_if_valid()` / `nvmetr_destroy_qp_if_valid()`)は
変更していない。

opcode と入出力構造体は **OptiPlex に入っていた
`/usr/src/linux-headers-7.0.0-29/include/linux/mlx5/mlx5_ifc.h` を実際に読んで
確認した**(clone は不要だった)。4 つとも 16 バイト入力・byte9-11 に 24bit の
ID という同じ形なので、`mlx5_destroy_obj24()` 1 本にまとめてある。

| 確保 | 解放 | opcode |
|---|---|---|
| `mlx5_alloc_uar()` | DEALLOC_UAR | 0x803 |
| `mlx5_alloc_pd()` | DEALLOC_PD | 0x801 |
| `mlx5_create_mkey_pa_rw()` | DESTROY_MKEY | 0x202 |
| `mlx5_create_cq()` | DESTROY_CQ | 0x401 |

解放順は依存の逆順で **QP → MKey → CQ → PD → UAR**。MKey は PD に属し CQ は
UAR を参照するので、PD/UAR を先に返してはいけない。**DESTROY_MKEY が取るのは
mkey ではなくインデックス**なので、`mlx5_create_mkey_pa*()` が保持している
`index << 8` を 8bit 戻して渡す。

EQ と TRANSPORT_DOMAIN の解放は**実装しなかった**。あれは
`mlx5_hca_bringup()` が作る Ethernet 用の資源で、プロセス生存中ずっと使うので
解放してはいけない(計画の表には載せていたが、対象外だった)。

**計画に無かった追加**: `mlx5_qp_create_rc()` / `mlx5_qp_create_ud_common()` の
失敗パスにもロールバックを入れた。ALLOC_UAR は成功したが ALLOC_PD で失敗、
といったときに、それまで取れたぶんが漏れていた。`mlx5_qp_destroy()` は
`qpn==0` でも残りを解放するので、そのまま呼ぶだけでよい。

## 実機での確認結果

検証用に `qploop <N>`(RC QP の作成 → RST2INIT → 破棄を N 回)を追加した。
**FW を一気に枯渇させると復旧が重い**ので、4 → 8 → 16 → 32 → 64 → 128 と
段階的に増やしている(合計 252 回)。

| | 実装前 | 実装後 |
|---|---|---|
| cqn | 19 → 286(単調増加) | **252 回すべて 19** |
| pdn | 18 → 269(単調増加) | **252 回すべて 18** |
| uarn | 17 → 268(単調増加) | **252 回すべて 17** |
| mkey | 0x1100 → 0x10c00(単調増加) | **252 回すべて 0x1100** |
| 使われた cqn の種類数 | 252 | **1** |

**252 回では枯渇しなかった**(上限まで到達させるのは危険なのでやめた)。
枯渇の再現より「再利用がゼロだったものが完全に再利用されるようになった」ことを
示すほうが安全で証拠として強い、と判断した。解放コマンドのエラーログもゼロ。

`bench 8,64,256 rw 8` を連続 2 回実行しても正常に確立し、スループットも
無回帰(4266/5598/5995/4324/6694/6040 と 4264/5801/5994/4321/6695/5815 —
いずれも従来値の測定ばらつきの範囲)。GSI(st=0x8)と RC の両方で
`cqn/pdn/uarn` が使い回されていることをログで確認した。

## 着手前の現状

`mlx5.c` が発行する解放コマンドは **`DESTROY_QP` のみ**。`mlx5_qp_create_rc()`
は 1 本の QP につき **UAR / PD / MKey / CQ** を新規に確保する
(`mlx5_qp_t` の `uarn` / `pdn` / `mkey` / `cqn`)が、どれも解放していない。

## なぜ要るか

QP を作り直すたびに FW 側のリソースが溜まる。**既に一度踏んでいる**:
`nvmerdmaconnect` を繰り返したときに `INIT2RTR_QP` が
`MLX5_CMD_STAT_BAD_RES_ERR`(0x05)で失敗し、`mlx5_qp_destroy()` を呼ぶよう
配線して解決した。**PD/MKey/CQ/UAR の蓄積は未解決のまま残っている**ので、
再接続を十分繰り返せば同じクラスの失敗が再発する。

## 設計

`mlx5.c` に対になる解放関数を作る。既存の alloc/create と同じ
`mlx5_cmd_exec()` パターンで、いずれも 16 バイト入出力の単純なコマンド:

| 確保 | 解放 | opcode(要確認) |
|---|---|---|
| `mlx5_alloc_uar()` | `mlx5_dealloc_uar()` | `DEALLOC_UAR` |
| `mlx5_alloc_pd()` | `mlx5_dealloc_pd()` | `DEALLOC_PD` |
| `mlx5_create_mkey_pa_rw()` | `mlx5_destroy_mkey()` | `DESTROY_MKEY` |
| `mlx5_create_cq()` | `mlx5_destroy_cq()` | `DESTROY_CQ` |
| `mlx5_create_eq()` | `mlx5_destroy_eq()` | `DESTROY_EQ` |
| `mlx5_alloc_transport_domain()` | `mlx5_dealloc_transport_domain()` | `DEALLOC_TRANSPORT_DOMAIN` |

**opcode と入出力構造体は `include/linux/mlx5/mlx5_ifc.h` を実際に取得して
確認すること**(`enum mlx5_cmd_opcode` と `struct mlx5_ifc_dealloc_*_in_bits`)。

`mlx5_qp_destroy()` を「QP に付随する資源も含めて全部返す」形へ拡張し、
解放順序は **依存の逆順**(QP → MKey → CQ → PD → UAR)にする。
`mlx5_qp_t` の各フィールドを 0 にしてから返り、二重解放を防ぐ。

## 落とし穴

- **`mlx5_hca_bringup()` が作る Ethernet 用の資源(EQ/PD/MKey/CQ/TIS/RQ/TIR/SQ/
  フローテーブル)と混ぜないこと。** あちらはプロセス生存中ずっと使うので
  解放してはいけない。今回の対象は `mlx5_qp_create_rc()` / `_gsi()` が
  QP ごとに確保するものだけ。
- **`pcie1 reset` 相当の操作は x86 VFIO 版には無い。** rpi5 側は PERST# を
  トグルできたが、こちらは VFIO なのでリセット手段が違う。FW 状態が壊れたら
  プロセスを終了して bind し直す(それでも駄目ならホスト電源断)。
  **解放漏れの検証で FW を枯渇させると復旧が重いので、少しずつ試す。**
- 解放が失敗しても致命的にしない(ログを出して続行)。切断経路で
  ブロックすると、これまで何度も踏んだ「後始末でハングする」パターンになる。

## 検証

1. `nvmerdmaconnect` を **20〜30 回連続**で実行し、`BAD_RES_ERR` が出ないこと。
   解放前は何回目で失敗するかを先に測っておくと、効果が定量的に言える。
2. `bench` のスループットが退行しないこと(解放は接続確立時にしか走らない
   ので影響しないはずだが、確認する)。

---

# 段階 4: D1 — NVMe-oF Discovery サービス 【完了】

## 着手前の確認事項への答え(2026-08-16)

計画が「最大の未確認事項」としていた**「Linux ホストから自作ターゲットへ到達
する経路があるか」の答えは「無い」**だった。

- **片方の PF を mlx5_core に残す → 不可能。** `0000:01:00.0` と `0000:01:00.1` は
  **同じ IOMMU グループ 2**(上流の `0000:00:01.0` ごと)に入っている。VFIO は
  IOMMU グループ単位でしか扱えないので、片方だけ vfio-pci にはできない。
  `readlink /sys/bus/pci/devices/0000:01:00.{0,1}/iommu_group` で確認できる。
- **別 NIC 経由 → 不可能。** Linux 側の NIC はオンボードの `enp2s0`
  (192.168.3.164/24)だけで、ConnectX の 2 ポートは DAC で互いに直結されている。
  192.168.101.0/24 へ出る物理経路が無い。

そこで**「実装 + Linux 由来パーサで検証」**を選んだ(ユーザー判断)。

## 検証手法: 相手側の構造体でパースさせる

`tools/disc_log_check.c` を追加した。**このリポジトリのコードを一切 include
せず**、Linux カーネルの `include/linux/nvme.h` の
`struct nvmf_disc_rsp_page_hdr` / `nvmf_disc_rsp_page_entry` だけを使って
バイト列をパースする独立プログラム。`nvmediscover dump` が出す 16 進を
食わせて読めることを確認する。

**これが「自作 initiator ↔ 自作 target だけで試すと両側が同じ間違い方をして
絶対に検出できない」穴(CRC32C で実際に踏んだ)への答え**になる。相手側実装が
使う構造体そのもので読めるなら、自作パーサの解釈が正しいかとは独立に妥当性が
言える。オフセットも `offsetof` で機械的に出力させ、それを `nvmet.h` / `nvme.h`
の定数として写した(推測していない)。

確認できた値: hdr は genctr=0 / numrec=8 / recfmt=16 / entries=1024、
entry は trsvcid=32 / subnqn=256 / traddr=512 / tsas=768、どちらも sizeof=1024。

## 実装

**ターゲット側(`nvmet.c`)**

- `nvmet_ctx_t.is_discovery` — Fabrics Connect(qid=0)のデータ
  (`struct nvmf_connect_data`、offset 256 から subsysnqn[256])が Discovery NQN
  なら立てる。`nvmet_admin_dispatch()` に in-capsule データを渡すよう引数を追加した。
- `nvmet_build_id_ctrl_disc()` — Discovery 用の Identify Controller。通常との
  違いは **CNTRLTYPE=2** / SUBNQN=Discovery NQN / NN=0 の 3 つだけ。
  MAXCMD / SGLS / IOCCSZ / IORCSZ は Fabrics に必須なので通常と同じ値を入れる。
- `nvmet_build_disc_log()` — Discovery Log Page。エントリは 1 個
  (trtype=TCP、adrfam は待ち受けアドレスの family、subtype=2、cntlid=0xFFFF、
  asqsz=32、trsvcid=待ち受けポート、traddr=自分の IP)。
- Get Log Page に **LID 分岐と LPO(オフセット)対応**を追加。

**イニシエータ側(`nvme.c`)**

- `nvme_ctx_t.discovery_mode` を立てて接続すると、Identify Controller の後に
  Discovery Log Page を **2 回**読む(ヘッダ 1024B → NUMREC を見て全体)。
  **IO キューは作らずに完了する。**
- `nvme_build_get_log_page_sqe()` を追加(NUMD は 0's based で cdw10/cdw11 に
  分割、LPO は cdw12/cdw13)。

## 実機で踏んだこと: discovery の後、ターゲットが一切 SYN を受け付けなくなった

**2 件とも「Discovery は IO キューを作らない」ことの波及だった。**

1. **IO キューの arm が早すぎた。** `io_armed = 1` を ICResp 送信直後に立てて
   いたが、その時点ではまだ subnqn を見ていないので Discovery かどうか分からない。
   Discovery は IO キューを作らないので arm しっぱなしになり、**次に来た通常接続の
   admin 用 SYN を IO キューの accept が食べた**(`[!] nvmet: IOキューで想定外の
   Fabricsコマンド (fctype=0x0)`)。arm を Fabrics Connect(qid=0)受理後へ移し、
   `is_discovery` なら arm しないようにした。
2. **CLOSE_WAIT で固まった。** Discovery セッションには切断を検出して次の接続待ちへ
   戻す io job が居ないので admin job 自身で面倒を見る必要がある。最初
   `TCP_CLOSED || TCP_TIME_WAIT` だけを見ていたが、**相手の FIN を受けた側は
   CLOSE_WAIT で止まり、自分が close するまで CLOSED にならない**。結果 admin job が
   CLOSE_WAIT のまま固まり、以後 listener が一切 SYN を受け付けなくなった。
   C1 で「リスナが居るポートには RST を返さない」ようにしてあるため、相手からは
   SYN が黙って捨てられるように見え、原因が分かりにくかった。

## 実機での確認結果

`nvmediscover dump` → `tcpbench` → `nvmediscover` → `tcpbench` の 4 コマンドを
連続実行し、**すべて成功・失敗ログゼロ**。

- Fabrics Connect が「Discovery コントローラ」と判定
- Identify Controller の **CNTRLTYPE=2**
- Get Log Page が 2 回(`lpo=0 要求=1024 返却=1024` → `lpo=0 要求=2048 返却=2048`)
- エントリ: trtype=3(TCP)/ adrfam=1(IPv4)/ subtype=2 / cntlid=0xffff /
  asqsz=32 / trsvcid="4421" / subnqn=実サブシステム / traddr="192.168.101.11"
- **`tools/disc_log_check`(Linux の構造体のみ)で PASS**
- discovery を挟んだ後の `tcpbench` も無回帰(write 8k 1081/1076、read 8k 2430/2414)

## 残っている限界

- **実ホストの `nvme discover` では試せていない**(上記のとおり経路が無い)。
  Linux の構造体でパースできることまでしか言えない。
- エントリは常に 1 個(サブシステムが 1 つしかないため)。
- Discovery NQN 以外の未知 subnqn を拒否していない(どの subnqn でも通常の
  サブシステムとして受理する)。

## 着手前の現状

コード中に discovery 関連は**一切無い**。ホストは必ず subnqn を手打ちする
必要があり、`nvme discover` が使えない。

## なぜ要るか

実運用の NVMe-oF で最も目立つ欠落。ホスト側の標準ツール
(`nvme discover -t tcp -a <ip> -s 4420`)との相互運用に直結する。
**自作 initiator ↔ 自作 target の閉じた検証では絶対に発見できない種類の
欠落**でもある(お互いに要求しないので)。

## 設計

Discovery コントローラは**通常のコントローラとほぼ同じ**で、違いは:

1. **subnqn が固定**: `nqn.2014-08.org.nvmexpress.discovery`
2. **Identify Controller で discovery controller であることを示す**
   (CNTRLTYPE=discovery、または旧来は `Identify` の一部フィールド)
3. **Get Log Page(LID=0x70 = Discovery Log Page)に実体を返す**
4. IO キューを作らない(admin のみ)

Discovery Log Page の構造体は
`include/linux/nvme.h` の `struct nvmf_disc_rsp_page_hdr` /
`struct nvmf_disc_rsp_page_entry` が真実の源。**必ず実際に取得して
バイトオフセットを確認すること。** ターゲット側実装の参照は
`drivers/nvme/target/discovery.c`。

エントリに入れる内容(このプロジェクトの構成なら 1 エントリで足りる):
trtype=TCP(または RDMA)、adrfam=IPv4/IPv6、subnqn=実サブシステムの NQN、
traddr=自分の IP、trsvcid=ポート番号、portid、cntlid=0xFFFF(dynamic)。

`nvmet.c` の実装方針:

- `nvmet_ctx_t` に「このセッションは discovery コントローラか」のフラグを持つ。
  Fabrics Connect の subnqn が discovery NQN なら立てる。
- `Get Log Page` の現在の実装は**ゼロ埋めを返すだけ**なので、そこに LID 分岐を
  足す(LID=0x70 なら discovery log、それ以外は従来通りゼロ埋め)。
- `Identify Controller` は discovery 用に別の内容を返す必要がある。既存の
  `nvmet_build_id_ctrl()` を分岐させる。

## 落とし穴

- **Get Log Page はページング(LPOL/LPOU オフセット)を要求される。** ホストは
  まずヘッダ(16 バイト)だけを読み、NUMREC を見てから全体を読み直す。
  **オフセット付きの読み出しに対応しないと `nvme discover` は動かない。**
  現在の実装は `numdl/numdu` から長さを出しているだけでオフセットを見ていない。
- **Discovery ポートを本番ポートと分けるか同居させるか**を先に決める。
  標準は 8009 番だが、このプロジェクトのシェルは `nvmet <port>` が 4421 固定
  前提(それ以外だと `tcpbench` が壊れる、`CLAUDE.md` 参照)。同一ポートで
  subnqn によって discovery と通常を切り替えるのが変更が少ない。
- **実ホストで検証すること。** 自作 initiator は discovery を要求しないので、
  自己ループバックでは何も検証できない。OptiPlex の Linux から
  `nvme discover -t tcp -a 192.168.101.11 -s 4421` を実行する。ただし
  **ConnectX は mlx5_core か vfio-pci のどちらか一方にしかバインドできない**
  ので、Linux から自作ターゲットへ繋ぐ経路をどう作るかを先に確認すること
  (rpi5 時代は `netsh portproxy` 相当の中継が必要だった。x86 では
  両ポートを自作ドライバが握っているため、**そのままでは Linux から
  到達できない可能性が高い**。ここが最大の未確認事項)。

## 先に確認すべきこと(着手前)

**Linux ホストから自作 NVMe/TCP ターゲットへ到達する経路があるか。**
無ければ D1 の検証手段が無いので、以下のどれかを先に決める:

- 片方の PF を mlx5_core に残し、もう片方を vfio-pci にする(可能か要確認)
- 別の NIC(オンボード等)経由で到達させる
- 検証を諦めて実装だけ行い、ワイヤキャプチャで妥当性を見る(弱い)

---

# 段階 5: A1 — ルーティング / ゲートウェイ 【完了】

## 実装結果(2026-08-17)

`netif_t` に `netmask` / `gateway` / `gateway6` を足し、**L3 の宛先はそのままに
L2 の宛先だけをルータへ向ける**「次ホップ」判定を入れた。判定は
`netif.h` の `netif_next_hop4()` / `netif_next_hop6()`(`static inline`、
アドレス演算のみ)にあり、実際に MAC を引く経路は 2 つ:

- `tcp.c` の `tcp_resolve_mac()` — TCP の送信 3 経路が全てここを通るので、
  この 1 箇所を次ホップ対応にすれば TCP は全部カバーできる。
- `netif.c` の `net_resolve_mac()` — UDP/シェルなどの冷たい経路用。
  `udptest` / `udptest6` をこちらへ寄せた。

**経路表は作らず、デフォルトゲートウェイ 1 本のみ。** `gateway == 0` を
「未設定」とし、そのときは分岐 1 個で従来どおり宛先を直接解決して抜ける。
ブロードキャスト(255.255.255.255)とマルチキャスト(224.0.0.0/4、ff00::/8)、
IPv6 リンクローカル(fe80::/10)はゲートウェイへ渡さない。

IPv6 は `gateway6_set` フラグを別に持っている。未設定判定を「16 バイトが全部 0」
でやると v6 送信のたびに 16 回走査することになるため。

## 検証をどう組んだか(この環境の制約への答え)

計画は「この群は現在の DAC 直結ループバックでは一切踏まない」と書いていて、
実際 2 ポートが同一リンク上にいる以上、**素直には「別セグメントの向こう側」を
作れない**。アドレス演算だけを確認するテストは書けるが、それでは
「宛先とゲートウェイが同じでも通ってしまう」ので A1 の本質を検証できない。

**答え: 対向 PF と同じ物理ポート(同じ `nic`/`nic_priv`/MAC)を共有する別名
インターフェースを 10.9.9.9 として一時登録する。** 既存の
`netif_resolve_frame_owner()` が受信フレームの宛先 IP を見て別名側へ回すので、
**宛先 IP(10.9.9.9)と次ホップ IP(192.168.101.11)が異なる状態で実データを
流せる**。この機構は元々「同一 NIC 上の別名インターフェース」のために既にあり、
新規に足したのは `netif_unregister()`(テスト後に外して元の状態へ戻す)だけ。

決定的な証拠は**どの IP を ARP したか**:

```
[TCP] connect: 10.9.9.9:6002 へSYN送信
[ARP] request 送信: who-has 192.168.101.11 tell 192.168.101.10   <- 宛先ではなくGW
routetest: 受信 65536/65536 バイト -- PASS(内容一致)
```

## 実機での確認結果(2026-08-17)

| 確認項目 | 結果 |
|---|---|
| `routetest` [1] gw 未設定 | **PASS**。次ホップ = 宛先(A1 前と同じ挙動) |
| `routetest` [2] 次ホップ選択 4 ケース | **PASS**(同一サブネット/サブネット外/ブロードキャスト/マルチキャスト) |
| `routetest` [3] サブネット外宛の MAC | **PASS**。10.9.9.9 の次ホップ MAC = `02:00:00:00:10:11`(= mlx5-pf1) |
| `routetest` [4] IPv6 | **PASS**。グローバル宛は gateway6、リンクローカル/マルチキャストは宛先 |
| `routetest` [5] エンドツーエンド | **PASS**。10.9.9.9:6002 へ 64KB 往復してバイト一致 |
| `tcp6test` / `rsttest` / `ping6` / `udptest` / `udptest6` | すべて **PASS**(退行なし) |
| `tcpbench 8,64,256 rw 8` ×2 | 退行なし(下表) |
| `bench 8,64,256 rw 8` | 退行なし。4342/5803/5999/4353/6786/6041 |

`tcpbench`(括弧内は `CLAUDE.md` の基準値):

| | 1 回目 | 2 回目 | 基準 |
|---|---|---|---|
| write 8k | 1055.2 | 1056.7 | (1025) |
| write 64k | 3418.4 | 3270.3 | (3309) |
| write 256k | 4007.3 | 4006.7 | (3968) |
| read 8k | 2357.9 | 2347.7 | (2334) |
| read 64k | 5041.8 | 5037.0 | (5024) |
| read 256k | 5264.8 | 5259.1 | (5242) |

**全セルが基準値以上**なので `git stash` による HEAD との A/B は行っていない
(退行が測定ドリフトに隠れている可能性を排除する必要が無い)。5% 以上の変化が
無いので `CLAUDE.md` の性能表は更新していない。

## 残っている限界

- **IPv6 のエンドツーエンドは解決までしか確認していない。** グローバル
  アドレスを名乗る手段がまだ無い(`ipv6_addr_is_ours()` はリンクローカルと
  要請ノードマルチキャストしか知らない)ため。B1(SLAAC)で
  `netif_t` にグローバルアドレスを持たせたら v4 と同じ形で確認できる。
- **本物のルータを越えてはいない。** 別名インターフェースは同じ物理ポート上に
  あるので、「ゲートウェイの MAC 宛に送ると届く」ことまでしか言えない。
  L3 の転送そのものは検証対象外(このスタックはルータではない)。
- 経路は 1 本のみ。宛先ごとに違うゲートウェイを使う構成には対応していない。

## 着手前の現状

`gateway` / `route` / `netmask` の概念がコードに無く、**宛先は常に同一リンク上に
いる前提**で ARP/NDP を引いていた(リポジトリ全体を grep して該当ゼロ)。

---

# 段階 6〜10: A2〜A6 — 実 LAN へ出すための基盤

**この群は現在の DAC 直結ループバックでは一切踏まない。** 実 LAN や別セグメント
へ出す計画が具体化した時点で着手する。着手するなら A2 → A3 → A4/A5/A6 の順。

## A2: ARP / NDP キャッシュのエージング

現在は一度入れたら永久に有効(`arp.c` に寿命処理なし、`ipv6.c` の
`ndp_cache_insert()` も同様)。相手の NIC 交換や IP 移動に追従できない。

- `arp_cache_entry_t` / `ndp_cache_entry_t` に `uint64_t inserted_ticks` を追加。
- lookup 時に `timeout_ms(inserted_ticks, ARP_CACHE_TTL_MS)` で失効させる。
  TTL は 60 秒程度(Linux の既定は 30〜60 秒相当)。
- **エージング契機を lookup 時だけにする**(定期スキャンのタイマを増やさない。
  このプロジェクトは協調ポーリングなので、周期処理を増やすとホットパスの
  レイテンシに乗る)。

## A3: 重複アドレス検出(ARP Probe / IPv6 DAD)

- IPv4: RFC 5227 の ARP Probe(sender IP = 0 で自分の IP を問う)を起動時に
  数回送り、応答があれば衝突として警告する。
- IPv6: **DAD は RFC 4862 で必須**。リンクローカルを使う前に、自分自身の
  アドレスを target とする NS を**送信元アドレス `::`** で送り、NA が返って
  こないことを確認する。
- `ipv6_link_local_addr()` は毎回 MAC から導出しているだけなので、
  「DAD 済みか」の状態を `netif_t` に持たせる必要がある。

**このプロジェクト固有の注意**: 過去に IPv6 のアドレスを追加した際、
**ユーザの PC が使っている IP と衝突させて LAN 全体を不通にした前例がある**。
新しいアドレスを実 LAN で使うときは、必ず事前にユーザへ空きを確認する。

## A4: 送信側の IP フラグメント

受信は破棄実装済み(`ip.c`)、送信は分割しない。TCP は MSS で回避できているので、
**実害があるのは UDP のみ**。

- `udp_send()` / `ip_send()` に、リンク MTU を超える場合の分割を追加。
- IPv6 は経路上で分割しないので、**送信元での分割は Fragment 拡張ヘッダ**に
  なる(B4 と一緒にやるのが自然)。

優先度は低い。このスタックが大きい UDP を送る用途は今のところ無い。

## A5: ICMP Time Exceeded / Fragmentation Needed

- **Time Exceeded**: TTL が 0 になった転送時に返す。**このスタックはルータでは
  ないので転送しない** → 実質不要。ただし受信側で「自分宛の Time Exceeded」を
  ログに出す価値はある(経路異常の切り分け)。
- **Fragmentation Needed(code 4)**: DF 付きで MTU を超えるパケットを転送する
  ときに返す。これも転送しないので送信側は不要。**受信して PMTU を学習する側**
  が本命(A6 と対)。

## A6: ICMPv6 Packet Too Big + Path MTU Discovery

**IPv4 より深刻。** IPv6 は経路上で分割しない仕様なので、PMTUD が無いと
MTU の小さい経路で**通信が完全に成立しない**(v4 なら経路が分割してくれる)。

- ICMPv6 type 2(Packet Too Big)を受信したら、報告された MTU を宛先ごとに
  記憶し、以後その宛先への送信 MSS を下げる。
- 記憶先は近隣キャッシュと同じ粒度で良い(`ndp_cache_entry_t` に `pmtu` を追加)。
- TCP は `conn->snd_mss` を下げれば効く。`tcp_mss_cap_for()` に PMTU を
  反映させる。

**落とし穴**: MSS を途中で下げると、既に送信済み・未確認のセグメントとの
整合が要る。単純に「以後の新規セグメントから小さくする」で良い(TCP は
セグメント境界を自由に変えてよい)。

---

# 段階 11〜14: B系 — IPv6 として標準的に期待されるもの

## B1: Router Solicitation / Advertisement + SLAAC

現在はリンクローカルのみ。グローバルアドレスを自動取得できない。

- RS(type 133)を `ff02::2` へ送り、RA(type 134)の Prefix Information
  オプションからプレフィックスを取り出して EUI-64 と結合する。
- `netif_t` に「グローバルアドレス」を持たせる必要がある。現在 IPv6 アドレスは
  `netif_t` に持たず MAC から毎回導出しているので、**ここで初めて状態を持つ**
  ことになる(`netif_find_by_ip6()` もグローバルアドレスを見るよう拡張が要る)。

## B2: MLD(Multicast Listener Discovery)

要請ノードマルチキャストをスイッチが転送してくれない環境で NDP が通らなくなる。
DAC 直結では不要だが、実スイッチ配下では要る。MLDv2(type 143)の Report を
参加時に送る。

## B3: 近隣到達不能検出(NUD)

A2(エージング)の IPv6 版だが、NDP は「到達性を能動的に確認する」状態機械
(REACHABLE / STALE / PROBE)を持つ点が ARP と違う。A2 で単純な TTL 失効を
入れるなら、B3 は「STALE になったら単発 NS で確認する」程度で十分。

## B4: IPv6 拡張ヘッダ / フラグメント

`ipv6_handle_frame()` は `next_header` を素で見ているだけで、Hop-by-Hop や
Routing、Fragment が付いた実パケットを落とす。

- 拡張ヘッダのチェーンを辿って上位プロトコルまで到達する処理を追加。
- Fragment ヘッダは**再構成せず破棄**で良い(IPv4 側と同じ方針。ただし
  破棄したことをログに出す)。

---

## 参考: 今回の調査で確認した現状(実測値、2026-08-16 時点)

```
nvmet が対応する admin opcode: Identify(CNS=Controller/Namespace のみ),
                               Set Features, Get Log Page(ゼロ埋め),
                               Async Event(保留), Keep Alive
nvmet が対応する IO opcode   : Flush, Write, Read
TCP オプション               : MSS, Window Scale, NOP, END(SACK/Timestamps 無し)
ICMPv6 type                  : Echo Request/Reply, NS, NA(RS/RA/MLD/PTB 無し)
mlx5 の解放コマンド          : DESTROY_QP のみ
ルーティング                 : 概念なし(同一リンク前提。段階 5 = A1 で解消)
```

## この計画に含めなかったもの(意図的)

- **D2〜D9(Get Features、Identify の CNS 網羅、TRIM/Write Zeroes、
  SMART ログ、AER の完了、Keep Alive タイマ強制、複数名前空間、認証/TLS)**:
  ユーザ指定の順序に含まれていない。D1 の後に必要になったら別途。
- **C3(SACK/Timestamps)、C4(Keepalive)、C5(listen backlog)**: 同上。
  C2 を入れた後に効果を測ってから判断するのが妥当。
