# プロトコル未実装項目の実装計画

このリポジトリの TCP/IP・NVMe-oF スタックで「本来サポートすべきだが未実装」の
項目を、着手順に並べた計画書。**セッションをまたいで引き継ぐためのもの**なので、
各項目に「なぜ要るか / どこを触るか / どう検証するか / この環境固有の落とし穴」を
書いてある。

実装順は **C1/C2 → E → D1 → A1〜A6 → B系**(ユーザ指定)。

## 進捗

| 段階 | 項目 | 状態 |
|---|---|---|
| 1 | C1 TCP RST 送信 | 未着手 |
| 2 | C2 高速再送/高速回復 | 未着手 |
| 3 | E RDMA リソース解放 | 未着手 |
| 4 | D1 NVMe-oF Discovery サービス | 未着手 |
| 5 | A1 ルーティング/ゲートウェイ | 未着手 |
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
| `ts mask <mask> <value>` | ts_log の絞り込みダンプ(タグは File#\|Func#\|info) |
| `monitor` / `err` | HW 状態・エラーカウンタ |

---

# 段階 1: C1 — 閉じたポートへの SYN に RST を返す

## 現状

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

# 段階 2: C2 — 高速再送 / 高速回復(dup ACK)

## 現状

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

# 段階 3: E — RDMA リソースの解放

## 現状

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

# 段階 4: D1 — NVMe-oF Discovery サービス

## 現状

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

# 段階 5〜10: A1〜A6 — 実 LAN へ出すための基盤

**この群は現在の DAC 直結ループバックでは一切踏まない。** 実 LAN や別セグメント
へ出す計画が具体化した時点で着手する。着手するなら A1 → A2 → A3 → A4/A5/A6 の順
(A1 が無いと他が意味を持ちにくい)。

## A1: ルーティング / ゲートウェイ

`gateway` / `route` / `netmask` の概念がコードに無く、**宛先は常に同一リンク上に
いる前提**で ARP/NDP を引いている。

- `netif_t` に `netmask` と `gateway` を追加。
- 送信時、宛先が自分のサブネット外なら **ゲートウェイの MAC を引く**
  (`tcp_resolve_mac()` / `udp_send()` / `ip_send()` の共通前段に入れる)。
- 経路表は 1 エントリ(デフォルトゲートウェイ)で十分。汎用の routing table は
  このプロジェクトの用途では過剰。

**触る場所**: `netif.h`(フィールド追加)、`tcp.c` の `tcp_resolve_mac()`、
`ip.c` の `ip_send()`、`ipv6.c` の `ndp_resolve()` 呼び出し側。

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
ルーティング                 : 概念なし(同一リンク前提)
```

## この計画に含めなかったもの(意図的)

- **D2〜D9(Get Features、Identify の CNS 網羅、TRIM/Write Zeroes、
  SMART ログ、AER の完了、Keep Alive タイマ強制、複数名前空間、認証/TLS)**:
  ユーザ指定の順序に含まれていない。D1 の後に必要になったら別途。
- **C3(SACK/Timestamps)、C4(Keepalive)、C5(listen backlog)**: 同上。
  C2 を入れた後に効果を測ってから判断するのが妥当。
