# AS のデータ（KASN1）

kanmon が宛先の AS・回線の種類・登録国を手元で引くためのデータの作り方です（v0.5.1〜）。

## 流れ

1. kanmon-data リポジトリの CI（`asn-data.yml`。ここにあるのは控え）が週 1 回、iptoasn.com から `ip2asn-combined.tsv.gz` を取る
2. `build_asn.py` で縮める
   - 範囲・AS 番号・国は全部残す（A5 の「初めての AS」と R1 の回線の種類に要る）
   - AS の名前は、`detections/22-asn.yaml` の `cloud_asns`・`cdn_asns`・`residential_asns` にある AS だけ残す
   - AS 0（経路なし）を捨て、隣り合う同じ AS の範囲をまとめる
3. Release「asn-data」の `asn.kasn.gz` と `asn.kasn.gz.sha256` を差し替える（変わったときだけ）
4. kanmond は 7 日ごと（端末ごとに最大 1 日ずらす）に `.sha256` だけを取り、変わっていれば本体を取る

利用者が各自 iptoasn.com から取ると、無料で運営されているサービスに負荷がかかります。そのため、取りに行くのは CI の週 1 回だけにしています。

## 大きさ（2026-11-19 の実測）

| | 大きさ |
|---|---|
| 元データ（gzip） | 11.0 MB |
| KASN1（展開後） | 9.0 MB |
| KASN1（gzip、配布するもの） | 3.2 MB |

範囲は v4 約 41 万件・v6 約 9 万件（まとめた後）、AS は約 8.7 万件です。kanmond での読み込みは約 50ms でした。

## 手元で作る

```sh
curl -fsSLO https://iptoasn.com/data/ip2asn-combined.tsv.gz
python3 tools/asn-data/build_asn.py --tsv ip2asn-combined.tsv.gz \
  --lists detections/22-asn.yaml --out asn.kasn.gz
```

作ったファイルは、`kanmon.toml` の `[asn] file = "..."` で読ませられます（このときは取得しません）。

## ライセンス

元データは [iptoasn.com](https://iptoasn.com/) のもので、Public Domain（PDDL v1.0）です。
