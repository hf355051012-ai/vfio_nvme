#!/usr/bin/env python3
"""sniff_neigh.py -- 対向ホスト(Pi5)で近隣探索のフレームを観測する。

**到達確認(NUD)がユニキャストで出ているか**は、送信直前か相手側でしか
見えない。`nudtest` は送信直前の観測フックで見ているが、それだけだと
「自作の観測を自作が信じる」形になる。ここで**相手側の L2 宛先を実際に読む**
ことで、ワイヤ上で本当にユニキャストになっていることを確かめる。

  使い方(Pi5 上で root):
    sudo python3 sniff_neigh.py [インターフェース] [秒数]
    例: sudo python3 sniff_neigh.py eth2 20

  出力する種別:
    ARP request / reply         -- L2 宛先がブロードキャストかユニキャストか
    ICMPv6 NS / NA              -- 同上(NS は 33:33:ff:.. がマルチキャスト)

  注意: br0 のポート(eth1/eth2)では **ETH_P_ALL(3)でないと 1 フレームも
  受信できない**(bridge の rx_handler が先に消費する)。
"""

import socket
import sys
import time

BCAST = b"\xff\xff\xff\xff\xff\xff"


def is_multicast(mac):
    return (mac[0] & 0x01) != 0


def fmt(mac):
    return ":".join("%02x" % b for b in mac)


def main():
    ifname = sys.argv[1] if len(sys.argv) > 1 else "eth2"
    secs = float(sys.argv[2]) if len(sys.argv) > 2 else 20.0

    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    s.bind((ifname, 0))
    s.settimeout(0.5)

    end = time.time() + secs
    counts = {"arp-uni": 0, "arp-bcast": 0, "ns-uni": 0, "ns-mcast": 0}
    print("近隣探索を %s で %.0f 秒観測します" % (ifname, secs))
    while time.time() < end:
        try:
            d = s.recv(65535)
        except socket.timeout:
            continue
        if len(d) < 42:
            continue
        dst, src, etype = d[0:6], d[6:12], d[12:14]

        if etype == b"\x08\x06":                      # ARP
            oper = int.from_bytes(d[20:22], "big")
            spa = ".".join(str(b) for b in d[28:32])
            tpa = ".".join(str(b) for b in d[38:42])
            if oper == 1:
                uni = dst != BCAST
                counts["arp-uni" if uni else "arp-bcast"] += 1
                print("ARP request  who-has %s tell %s  L2宛先=%s (%s)"
                      % (tpa, spa, fmt(dst), "ユニキャスト" if uni else "ブロードキャスト"))
            elif oper == 2:
                print("ARP reply    %s is-at %s  L2宛先=%s" % (spa, fmt(src), fmt(dst)))
            continue

        if etype != b"\x86\xdd" or len(d) < 14 + 40 + 24:
            continue
        if d[14 + 6] != 58:                            # ICMPv6(拡張ヘッダ無しのみ)
            continue
        t = d[14 + 40]
        if t not in (135, 136):
            continue
        target = socket.inet_ntop(socket.AF_INET6, d[14 + 48:14 + 64])
        if t == 135:
            uni = not is_multicast(dst)
            counts["ns-uni" if uni else "ns-mcast"] += 1
            print("ICMPv6 NS    target=%s  L2宛先=%s (%s)"
                  % (target, fmt(dst), "ユニキャスト" if uni else "マルチキャスト"))
        else:
            flags = d[14 + 44]
            print("ICMPv6 NA    target=%s  S=%d O=%d  L2宛先=%s"
                  % (target, 1 if flags & 0x40 else 0, 1 if flags & 0x20 else 0, fmt(dst)))

    print("集計: ARP request ユニキャスト=%d ブロードキャスト=%d / "
          "NS ユニキャスト=%d マルチキャスト=%d"
          % (counts["arp-uni"], counts["arp-bcast"],
             counts["ns-uni"], counts["ns-mcast"]))


if __name__ == "__main__":
    main()
