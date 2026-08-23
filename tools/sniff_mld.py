#!/usr/bin/env python3
"""sniff_mld.py -- 対向ホスト(Pi5)で MLD を観測し、MLDDUMP 形式で吐く。

用途は 2 つある。

 1. **自作の Report が本当にワイヤへ出ているかを相手側で確かめる。**
    Pi5 には tcpdump が無い。
 2. **Linux 自身が出した MLD を `tools/mld_check` に食わせる。**
    mld_check の MLDv2 レコード定義は Linux の include/net/mld.h からの
    転記(あのヘッダはユーザ空間から include できない)なので、
    **Linux が送ったバイト列を同じツールで読めること**が転記の検算になる。

  使い方(Pi5 上で root):
    sudo python3 sniff_mld.py [インターフェース] [秒数]
    例: sudo python3 sniff_mld.py eth2 20

  注意: br0 のポート(eth1/eth2)では **ETH_P_ALL(3)でないと 1 フレームも
  受信できない**。bridge の rx_handler がフレームを先に消費するので、
  プロトコル別の配送まで届かない。
"""

import socket
import sys
import time

NH_HOP = 0
NH_ROUTING = 43
NH_FRAGMENT = 44
NH_NONE = 59
NH_DEST = 60
NH_ICMPV6 = 58

MLD_TYPES = {130: "Query", 131: "v1 Report", 132: "v1 Done", 143: "v2 Report"}


def skip_ext(buf, off, nh):
    """拡張ヘッダを飛ばして (上位プロトコル番号, オフセット, RouterAlert) を返す。"""
    ra = False
    for _ in range(8):
        if nh in (NH_ICMPV6, 6, 17):
            return nh, off, ra
        if nh in (NH_NONE, NH_FRAGMENT):
            return None, off, ra
        if nh not in (NH_HOP, NH_ROUTING, NH_DEST):
            return None, off, ra
        if off + 2 > len(buf):
            return None, off, ra
        nxt = buf[off]
        hlen = (buf[off + 1] + 1) * 8
        if nh == NH_HOP:
            p = off + 2
            while p < off + hlen:
                t = buf[p]
                if t == 0:            # PAD1 は長さフィールドを持たない
                    p += 1
                    continue
                if p + 2 > off + hlen:
                    break
                if t == 5:            # Router Alert
                    ra = True
                p += 2 + buf[p + 1]
        nh = nxt
        off += hlen
    return None, off, ra


def main():
    ifname = sys.argv[1] if len(sys.argv) > 1 else "eth2"
    secs = float(sys.argv[2]) if len(sys.argv) > 2 else 20.0

    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    s.bind((ifname, 0))
    s.settimeout(0.5)

    end = time.time() + secs
    seen = 0
    print("MLD を %s で %.0f 秒観測します" % (ifname, secs))
    while time.time() < end:
        try:
            d = s.recv(65535)
        except socket.timeout:
            continue
        if len(d) < 14 + 40 or d[12:14] != b"\x86\xdd":
            continue
        nh, off, ra = skip_ext(d, 14 + 40, d[14 + 6])
        if nh != NH_ICMPV6 or off >= len(d):
            continue
        t = d[off]
        if t not in MLD_TYPES:
            continue
        plen = int.from_bytes(d[14 + 4:14 + 6], "big")
        end_off = 14 + 40 + plen
        msg = d[off:end_off]
        src = socket.inet_ntop(socket.AF_INET6, d[14 + 8:14 + 24])
        dst = socket.inet_ntop(socket.AF_INET6, d[14 + 24:14 + 40])
        hop = d[14 + 7]
        seen += 1
        print("MLD %s  src=%s dst=%s hop_limit=%d router_alert=%d"
              % (MLD_TYPES[t], src, dst, hop, 1 if ra else 0))
        print("MLDDUMP len=%d %s" % (len(msg), " ".join("%02x" % b for b in msg)))
    print("MLD を %d 個観測しました" % seen)


if __name__ == "__main__":
    main()
