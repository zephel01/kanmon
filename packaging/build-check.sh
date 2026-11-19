# shellcheck shell=bash
# 導入スクリプトから読み込む：target/release の実行ファイルが、このリポジトリの版でビルドされているかを確かめる。
# 古いバイナリのまま導入して取り残される（リポジトリは新しいのに v0.2.5 が動いていた）のを防ぐ。
# 自動ではビルドしない（sudo で cargo を動かすと target が root の持ち物になるため）。

# 使い方：check_build_version <リポジトリの根>
check_build_version() {
  local root="$1" want got bin
  want=$(sed -n '/^\[workspace\.package\]/,/^\[/s/^version *= *"\([^"]*\)".*/\1/p' "$root/Cargo.toml" | head -n 1)
  if [ -z "$want" ]; then
    echo "Cargo.toml から版を読めません" >&2
    return 1
  fi
  for bin in kanmond kanmonctl; do
    if [ ! -x "$root/target/release/$bin" ]; then
      echo "target/release/$bin がありません。先に cargo build --release を実行してください（sudo なしで）" >&2
      return 1
    fi
    got=$("$root/target/release/$bin" --version 2>/dev/null | awk '{print $2}')
    if [ "$got" != "$want" ]; then
      echo "target/release/$bin の版（${got:-不明}）がリポジトリの版（$want）と違います。" >&2
      echo "先に cargo build --release を実行してください（sudo なしで）" >&2
      return 1
    fi
  done
}
