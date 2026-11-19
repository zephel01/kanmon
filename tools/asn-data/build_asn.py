#!/usr/bin/env python3
"""iptoasn.com の ip2asn-combined.tsv(.gz) から、kanmon の AS データ（KASN1）を作る。

使い方:
  python3 build_asn.py --tsv ip2asn-combined.tsv.gz --lists detections/22-asn.yaml --out asn.kasn.gz

- 範囲・AS 番号・国は全部入れる（A5 の「初めての AS」と R1 の回線の種類に要る）
- AS の名前は、--lists のクラウド・CDN・住宅用の一覧にある AS だけ入れる（容量を減らすため）
- AS 0（経路なし）は捨て、隣り合う同じ AS の範囲はまとめる
- 出力の SHA-256 を <out>.sha256 に書く（kanmond はこれを照合する）
標準ライブラリだけで動く。形式は crates/kanmon-core/src/asn.rs と合わせる。
"""
import argparse
import gzip
import hashlib
import ipaddress
import re
import struct
import sys

MAGIC = b"KASN1\0\0\0"
LISTS = ("cloud_asns", "cdn_asns", "residential_asns")
MAX_NAME = 256


def read_lists(path):
    """22-asn.yaml から、名前を残す AS 番号を拾う（PyYAML なしで読む）"""
    text = open(path, encoding="utf-8").read()
    keep = set()
    for name in LISTS:
        m = re.search(rf"^\s*{name}:\s*\[(.*?)\]", text, re.S | re.M)
        if not m:
            sys.exit(f"{path}: {name} が見つかりません")
        keep.update(int(x) for x in re.findall(r'"(\d+)"', m.group(1)))
    return keep


def merge(rows):
    rows.sort()
    out = []
    for s, e, a in rows:
        if out and s <= out[-1][1]:
            continue  # 重なりは後を捨てる
        if out and out[-1][2] == a and out[-1][1] + 1 == s:
            out[-1] = (out[-1][0], e, a)
        else:
            out.append((s, e, a))
    return out


def build(tsv_path, keep):
    opener = gzip.open if tsv_path.endswith(".gz") else open
    v4, v6, names, bad = [], [], {}, 0
    with opener(tsv_path, "rt", encoding="utf-8", errors="replace") as f:
        for line in f:
            p = line.rstrip("\n").split("\t")
            if len(p) < 3:
                bad += 1
                continue
            try:
                asn = int(p[2])
                s, e = ipaddress.ip_address(p[0]), ipaddress.ip_address(p[1])
            except ValueError:
                bad += 1
                continue
            if asn == 0 or s.version != e.version or int(s) > int(e):
                continue
            (v4 if s.version == 4 else v6).append((int(s), int(e), asn))
            if asn not in names:
                cc = p[3].strip() if len(p) > 3 else ""
                cc = cc.encode() if len(cc) == 2 and cc.isascii() and cc.isupper() else b"\0\0"
                desc = ""
                if asn in keep and len(p) > 4:
                    desc = "".join(ch for ch in p[4].strip() if ch.isprintable())
                    while len(desc.encode()) > MAX_NAME:
                        desc = desc[:-1]
                names[asn] = (cc, desc)
    v4, v6 = merge(v4), merge(v6)
    if not v4 and not v6:
        sys.exit("有効な行がありません（形式変更の可能性）")
    out = bytearray(MAGIC)
    out += struct.pack("<III", len(v4), len(v6), len(names))
    for s, e, a in v4:
        out += struct.pack("<III", s, e, a)
    for s, e, a in v6:
        out += s.to_bytes(16, "little") + e.to_bytes(16, "little") + struct.pack("<I", a)
    for a in sorted(names):
        cc, d = names[a]
        db = d.encode()
        out += struct.pack("<I", a) + cc + struct.pack("<H", len(db)) + db
    return bytes(out), (len(v4), len(v6), len(names), sum(1 for x in names.values() if x[1]), bad)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--tsv", required=True)
    ap.add_argument("--lists", required=True, help="detections/22-asn.yaml")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    raw, (n4, n6, na, named, bad) = build(a.tsv, read_lists(a.lists))
    # mtime=0 にして、同じ入力なら同じ出力（SHA-256）になるようにする
    gz = gzip.compress(raw, compresslevel=9, mtime=0)
    open(a.out, "wb").write(gz)
    sha = hashlib.sha256(gz).hexdigest()
    open(a.out + ".sha256", "w").write(f"{sha}  {a.out.rsplit('/', 1)[-1]}\n")
    print(f"v4 {n4} / v6 {n6} / AS {na}（名前あり {named}）/ 読めない行 {bad}")
    print(f"展開後 {len(raw)/1e6:.2f} MB / gzip {len(gz)/1e6:.2f} MB / sha256 {sha}")


if __name__ == "__main__":
    main()
