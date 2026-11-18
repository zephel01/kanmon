//! パッケージの更新差分の静的検査（`kanmonctl inspect`）の OS 非依存部分。
//!
//! パッケージ（PyPI の wheel・sdist、npm の tarball）の「指定した版」と「1 つ前の版」の差分を取り、
//! 増えた部分だけから特徴（`.pth`・install スクリプト・難読化・環境変数の収集・認証ファイル・
//! 外への送り先 等）を拾う。所見は 1 件のイベント（`network.kind = inspect`）にまとめ、
//! 既存の検知エンジン（`detections/70-inspect.yaml`）で点数を付ける。
//!
//! ここは純関数だけ：ファイル・ネットワーク・時計には触らない（時刻は引数で受け取る）。
//! アーカイブの読み出しとレジストリからの取得は kanmonctl 側にある。
//! 入力はすべて攻撃者が作ったものとして扱う。パッケージのコードは実行も import もしない。

pub mod diff;
pub mod eco;
pub mod event;
pub mod features;

use serde::Serialize;

/// アーカイブの 1 エントリ（正規化前のパス）
#[derive(Debug, Clone)]
pub struct Entry {
    pub path: String,
    pub data: Vec<u8>,
    /// シンボリックリンク・ハードリンク・デバイス等、通常ファイル以外だった（中身は読んでいない）
    pub special: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Ecosystem {
    Pypi,
    Npm,
}

impl Ecosystem {
    pub fn as_str(&self) -> &'static str {
        match self {
            Ecosystem::Pypi => "pypi",
            Ecosystem::Npm => "npm",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Change {
    Added,
    Changed,
    Removed,
}

/// 差分の 1 件（正規化後のパス）
#[derive(Debug, Clone)]
pub struct FileDiff {
    pub path: String,
    pub change: Change,
    pub old: Option<Vec<u8>>,
    pub new: Option<Vec<u8>>,
}

/// 所見の 1 件。`feature` は特徴の識別子（`pth_exec`・`env_harvest` 等）
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Finding {
    pub feature: String,
    pub path: String,
    /// 1 始まり。ファイル全体に対する所見は None
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    /// 該当箇所の抜粋（最大 200 文字、制御文字は除く）
    pub excerpt: String,
}

impl Finding {
    pub fn new(feature: &str, path: &str, line: Option<usize>, excerpt: &str) -> Self {
        Self { feature: feature.into(), path: path.into(), line, excerpt: excerpt_of(excerpt) }
    }
}

/// 抜粋を作る：制御文字（改行・ESC 等）を空白にし、200 文字で切る。
/// 攻撃者の文字列で端末を操作させないため、表示前に必ず通す
pub fn excerpt_of(s: &str) -> String {
    let t: String = s.chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
    let t = t.split_whitespace().collect::<Vec<_>>().join(" ");
    if t.chars().count() > 200 {
        format!("{}…", t.chars().take(200).collect::<String>())
    } else {
        t
    }
}

/// 版の付帯情報（レジストリから。手元のファイルを調べるときは空）
#[derive(Debug, Clone, Default, Serialize)]
pub struct Meta {
    pub name: String,
    pub version: String,
    pub base_version: Option<String>,
    /// 公開時刻（UNIX 秒）
    pub published: Option<i64>,
    pub base_published: Option<i64>,
    /// npm の公開者（`_npmUser.name`）
    pub publisher: Option<String>,
    pub base_publisher: Option<String>,
    /// npm の `dist.attestations` の有無
    pub attested: Option<bool>,
    pub base_attested: Option<bool>,
}

/// 展開の上限
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// 圧縮されたアーカイブの大きさ
    pub max_compressed: u64,
    /// 展開後の合計
    pub max_total: u64,
    pub max_entries: usize,
    /// これを超えるファイルは中身を読まず、所見 `oversize_file` にする
    pub max_file: u64,
    /// 展開後 / 圧縮 の比
    pub max_ratio: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_compressed: 50 * 1024 * 1024,
            max_total: 200 * 1024 * 1024,
            max_entries: 20_000,
            max_file: 20 * 1024 * 1024,
            max_ratio: 100,
        }
    }
}

/// パッケージ名が正しい形か（URL・パスに入れる前に必ず確かめる）
pub fn valid_name(eco: Ecosystem, name: &str) -> bool {
    let ok_body = |s: &str, extra: &[char], max: usize| {
        let b: Vec<char> = s.chars().collect();
        !b.is_empty()
            && b.len() <= max
            && b[0].is_ascii_alphanumeric()
            && b.iter().all(|c| c.is_ascii_alphanumeric() || extra.contains(c))
    };
    match eco {
        Ecosystem::Pypi => {
            ok_body(name, &['.', '_', '-'], 100) && name.chars().last().is_some_and(|c| c.is_ascii_alphanumeric())
        }
        Ecosystem::Npm => {
            if name != name.to_ascii_lowercase() {
                return false;
            }
            let extra = ['.', '_', '~', '-'];
            match name.strip_prefix('@') {
                Some(rest) => match rest.split_once('/') {
                    Some((scope, pkg)) => ok_body(scope, &extra, 100) && ok_body(pkg, &extra, 100),
                    None => false,
                },
                None => ok_body(name, &extra, 100),
            }
        }
    }
}

/// 版が正しい形か
pub fn valid_version(v: &str) -> bool {
    let b: Vec<char> = v.chars().collect();
    !b.is_empty()
        && b.len() <= 64
        && b[0].is_ascii_alphanumeric()
        && b.iter().all(|c| c.is_ascii_alphanumeric() || ['.', '+', '!', '_', '-'].contains(c))
}

/// `pypi:name==ver` / `npm:name@ver` / `npm:@scope/name@ver` を分解する（版は省略可）
pub fn parse_spec(s: &str) -> anyhow::Result<(Ecosystem, String, Option<String>)> {
    let (eco, rest) = if let Some(r) = s.strip_prefix("pypi:") {
        (Ecosystem::Pypi, r)
    } else if let Some(r) = s.strip_prefix("npm:") {
        (Ecosystem::Npm, r)
    } else {
        anyhow::bail!("`pypi:名前==版` か `npm:名前@版` の形で指定してください");
    };
    let (name, ver) = match eco {
        Ecosystem::Pypi => match rest.split_once("==") {
            Some((n, v)) => (n, Some(v)),
            None => (rest, None),
        },
        Ecosystem::Npm => {
            // スコープの @ を避けて、2 文字目以降の最後の @ で分ける
            match rest.get(1..).and_then(|t| t.rfind('@')).map(|i| i + 1) {
                Some(i) => (&rest[..i], Some(&rest[i + 1..])),
                None => (rest, None),
            }
        }
    };
    if !valid_name(eco, name) {
        anyhow::bail!("パッケージ名の形が正しくありません");
    }
    if let Some(v) = ver {
        if !valid_version(v) {
            anyhow::bail!("版の形が正しくありません");
        }
    }
    Ok((eco, name.to_string(), ver.map(str::to_string)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn specs() {
        assert_eq!(
            parse_spec("pypi:agent-framework==1.26.2").unwrap(),
            (Ecosystem::Pypi, "agent-framework".into(), Some("1.26.2".into()))
        );
        assert_eq!(
            parse_spec("npm:@tanstack/router@1.2.3").unwrap(),
            (Ecosystem::Npm, "@tanstack/router".into(), Some("1.2.3".into()))
        );
        assert_eq!(parse_spec("npm:keyv").unwrap(), (Ecosystem::Npm, "keyv".into(), None));
        assert_eq!(parse_spec("npm:@scope/pkg").unwrap(), (Ecosystem::Npm, "@scope/pkg".into(), None));
        assert_eq!(parse_spec("pypi:Foo.Bar_baz").unwrap().1, "Foo.Bar_baz");
        for bad in [
            "pypi:../x",
            "npm:a/b",
            "pypi:a b",
            "pypi:a\nb",
            "pypi:a%2f",
            "npm:a?x",
            "npm:a#x",
            "npm:keyv==6.0.0",
            "pypi:-x",
            "pypi:x-",
            "npm:Upper",
            "npm:@/x",
            "pypi:x==1.0;rm",
            "pip:x",
        ] {
            assert!(parse_spec(bad).is_err(), "{bad}");
        }
        assert!(parse_spec(&format!("pypi:{}", "a".repeat(101))).is_err());
    }

    #[test]
    fn excerpt_strips_control() {
        assert_eq!(excerpt_of("a\x1b[31mb\nc"), "a [31mb c");
        assert_eq!(excerpt_of(&"x".repeat(300)).chars().count(), 201);
    }
}
