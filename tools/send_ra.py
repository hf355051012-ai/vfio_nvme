#!/usr/bin/env python3
"""send_ra.py -- 対向ホスト(Pi5)から本物の Router Advertisement を送る。

`slaactest` は対向 PF にルータ役をさせるが、**RA を組んでいるのも自作コード**
なので、両側が同じ間違い方をしていれば PASS してしまう。この穴を塞ぐには
「自作でない送り手」が要る。Pi5 には radvd が入っていないので、AF_PACKET で
RA を直接組んで送る(CLAUDE.md の「RA の送り手は Pi5 で用意できる」の実体)。

  使い方(Pi5 上で root):
    sudo python3 send_ra.py [インターフェース] [valid秒] [router_lifetime秒] [回数]
    例: sudo python3 send_ra.py br0 1800 1800 3

    末尾に listen を付けると**ルータ役として常駐**し、Router Solicitation を
    受けたら RA を返す(RFC 4861 6.2.6)。Pi5 に tcpdump が無いので、
    「自作の RS が本当にワイヤへ出ているか」もこれで確認する。
    例: sudo python3 send_ra.py br0 1800 1800 3 listen

  送るもの: ff02::1 宛 / hop limit 255 / 送信元は br0 のリンクローカル
            オプション = Source Link-Layer Address + Prefix Information
                         (2001:db8:0:9::/64、L=1 A=1)+ MTU 9000

  期待する結果(OptiPlex の常駐シェル):
    ip6addr -> 各 PF に 2001:0db8:0000:0009: + EUI-64 が生える
    route   -> gateway6 が Pi5 の br0 リンクローカルになる
"""

import socket
import struct
import sys
import time

ALL_NODES_MAC = b"\x33\x33\x00\x00\x00\x01"
ALL_NODES_IP6 = bytes.fromhex("ff020000000000000000000000000001")
PREFIX = bytes.fromhex("20010db800000009") + b"\x00" * 8  # 2001:db8:0:9::/64
PREFIX_LEN = 64
LINK_MTU = 9000
NH_ICMPV6 = 58


def mac_of(ifname):
    with open("/sys/class/net/%s/address" % ifname) as f:
        return bytes(int(x, 16) for x in f.read().strip().split(":"))


def link_local_of(mac):
    """MAC から EUI-64 を作って fe80::/64 と結合する(Linux の既定と同じ)。"""
    eui = bytes([mac[0] ^ 0x02, mac[1], mac[2], 0xFF, 0xFE, mac[3], mac[4], mac[5]])
    return b"\xfe\x80" + b"\x00" * 6 + eui


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def build_ra(mac, src6, valid, preferred, router_lifetime):
    # 本体 16 バイト: type/code/cksum/cur hop limit/flags/router lifetime/
    #                 reachable time/retrans timer
    body = struct.pack("!BBHBBHII", 134, 0, 0, 64, 0x00, router_lifetime, 0, 0)
    # Source Link-Layer Address(8 バイト)
    opts = struct.pack("!BB", 1, 1) + mac
    # Prefix Information(32 バイト固定)
    opts += struct.pack("!BBBBIII", 3, 4, PREFIX_LEN, 0xC0, valid, preferred, 0)
    opts += PREFIX
    # MTU(8 バイト)
    opts += struct.pack("!BBHI", 5, 1, 0, LINK_MTU)

    msg = body + opts
    pseudo = src6 + ALL_NODES_IP6 + struct.pack("!IBBBB", len(msg), 0, 0, 0, NH_ICMPV6)
    cs = checksum(pseudo + msg)
    msg = msg[:2] + struct.pack("!H", cs) + msg[4:]

    ip6 = struct.pack("!IHBB", 0x60000000, len(msg), NH_ICMPV6, 255) + src6 + ALL_NODES_IP6
    eth = ALL_NODES_MAC + mac + b"\x86\xdd"
    return eth + ip6 + msg


def listen_and_reply(sock, frame, timeout_s):
    """Router Solicitation(ICMPv6 type 133)を待って RA を返す。

    自作側が RS を出しているかどうかは、**受け取った側でしか確かめられない**
    (Pi5 に tcpdump が無い)。ここで受信を数えることがその確認になる。
    """
    sock.settimeout(1.0)
    deadline = time.time() + timeout_s
    seen = 0
    while time.time() < deadline:
        try:
            data = sock.recv(65535)
        except socket.timeout:
            continue
        if len(data) < 14 + 40 + 4:
            continue
        if data[12:14] != b"\x86\xdd":
            continue
        if data[14 + 6] != NH_ICMPV6:      # next header
            continue
        if data[14 + 40] != 133:           # ICMPv6 type = Router Solicitation
            continue
        src = socket.inet_ntop(socket.AF_INET6, data[14 + 8:14 + 24])
        smac = ":".join("%02x" % b for b in data[6:12])
        hop = data[14 + 7]
        print("RS 受信: src=%s mac=%s hop_limit=%d -> RA を返します" % (src, smac, hop))
        seen += 1
        sock.send(frame)
    print("RS を %d 個受信しました" % seen)
    return seen


def main():
    args = sys.argv[1:]
    listen = bool(args) and args[-1] == "listen"
    if listen:
        args = args[:-1]
    ifname = args[0] if len(args) > 0 else "br0"
    valid = int(args[1]) if len(args) > 1 else 1800
    rlife = int(args[2]) if len(args) > 2 else 1800
    count = int(args[3]) if len(args) > 3 else 3
    preferred = min(valid, 900)

    mac = mac_of(ifname)
    src6 = link_local_of(mac)
    frame = build_ra(mac, src6, valid, preferred, rlife)

    # 受信に関わる落とし穴が 3 つある(どれも「送信は動くので気付かない」):
    #  1. protocol を省く(=0)と 1 フレームも受信できない。
    #  2. **htons() が要るのは socket() の第 3 引数だけ。** bind() のタプルに
    #     渡す番号は CPython 側が htons() するので、ここで掛けると二重変換に
    #     なる(0 なら socket() で指定したプロトコルがそのまま残る)。
    #  3. **ETH_P_IPV6 では駄目で ETH_P_ALL(3)が要る。** br0 のポートである
    #     eth1/eth2 では bridge の rx_handler がフレームを先に消費するため、
    #     プロトコル別の配送(ptype_base)まで届かない。ETH_P_ALL だけが
    #     bridge より手前(ptype_all)で受け取れる。br0 側で待っても、ホストが
    #     join していないマルチキャスト(ff02::2)は上がってこない。
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))
    s.bind((ifname, 0))

    if listen:
        print("ルータ役として待機します(%d 秒)" % (count * 10))
        listen_and_reply(s, frame, count * 10)
    else:
        for i in range(count):
            s.send(frame)
            print("RA 送信 %d/%d  if=%s src=%s prefix=2001:db8:0:9::/%d valid=%ds rlife=%ds"
                  % (i + 1, count, ifname,
                     socket.inet_ntop(socket.AF_INET6, src6), PREFIX_LEN, valid, rlife))
            if i + 1 < count:
                time.sleep(1)
    # tools/ra_check に読ませたいときのために 16 進も出す(書式は slaactest と同じ)。
    ra = frame[14 + 40:]
    print("RADUMP len=%d %s" % (len(ra), " ".join("%02x" % b for b in ra)))


if __name__ == "__main__":
    main()
