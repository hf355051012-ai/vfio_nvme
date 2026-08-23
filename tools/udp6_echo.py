#!/usr/bin/env python3
"""udp6_echo.py -- 対向ホスト(Pi5)で IPv6 UDP を待ち受け、届いた長さと
チェックサム(単純な加算)を報告する。

**自作の IPv6 断片化(B4)を Linux に再構成させて確かめる**ための受け皿。
自作 <-> 自作では、受信側が再構成を実装していないので「送った断片を自分で
組み直して一致した」までしか言えない。**Linux が組み直して上位まで届く**
ことが、断片の並び・オフセット・More フラグ・Identification が正しいことの
本物の証拠になる(CRC32C や NDP で踏んだ「両側が同じ間違いをする」穴を、
ここでも塞ぐ)。

  使い方(Pi5 上。root は不要):
    python3 udp6_echo.py [ポート] [秒数]
    例: python3 udp6_echo.py 7780 30

  出力:
    受信 len=4000 sum=0x... first=a0 last=..   -- 1 データグラムごと
"""

import socket
import sys
import time


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 7780
    secs = float(sys.argv[2]) if len(sys.argv) > 2 else 30.0

    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    s.bind(("::", port))
    s.settimeout(0.5)
    print("IPv6 UDP を :%d で %.0f 秒待ち受けます" % (port, secs))

    end = time.time() + secs
    n = 0
    while time.time() < end:
        try:
            data, addr = s.recvfrom(65535)
        except socket.timeout:
            continue
        n += 1
        # 送信側は big[i] = (i*31+7) & 0xff で埋めている。一致するか検算する。
        expect_ok = all(b == ((i * 31 + 7) & 0xFF) for i, b in enumerate(data))
        print("受信 %d: len=%d src=%s sum=0x%08x 先頭=%02x 末尾=%02x 内容一致=%s"
              % (n, len(data), addr[0], sum(data) & 0xFFFFFFFF,
                 data[0] if data else 0, data[-1] if data else 0,
                 "OK" if expect_ok else "NG"))
    print("合計 %d データグラムを受信しました" % n)


if __name__ == "__main__":
    main()
