# whois-lookup

**ドメイン・IP アドレス・AS 番号**の登録情報 — registrar、登録/更新/失効日、
ネームサーバー、abuse 連絡先 — をコマンドラインまたはローカル MCP サーバー
として調べるツール。

**RDAP ファースト**: クエリは公式 RDAP エンドポイント(構造化 JSON、IANA
bootstrap レジストリで解決)へ送り、RDAP 未対応の ccTLD のみ生の port 43
WHOIS にフォールバックします。**credential ゼロ・外部依存ゼロ** — すべての
データソースは公開エンドポイントで、バイナリは標準ライブラリのみです。

[asn-lookup](https://github.com/nlink-jp/asn-lookup)(帰属、オフライン)、
[abuse-lookup](https://github.com/nlink-jp/abuse-lookup)(評判)、
[tor-exit-lookup](https://github.com/nlink-jp/tor-exit-lookup)(Tor exit
判定)の姉妹品で、登録情報を担当します — 4 ツールで指標を 4 つの角度から
プロファイルできます。

> **Status: 開発中(プレリリース)。** CLI 骨格はビルド可能で下記のコマンド
> 体裁は確定済みですが、`lookup` / `cache` / `mcp` は未実装です。設計の全容は
> [docs/ja/whois-lookup-rfp.ja.md](docs/ja/whois-lookup-rfp.ja.md) を参照。

## 使い方(予定)

```console
$ whois-lookup lookup example.com
$ whois-lookup lookup 93.184.216.34 --json
$ whois-lookup lookup AS13335
$ whois-lookup lookup 日本語.jp        # IDN: 自前実装で punycode 変換
$ whois-lookup cache status
$ whois-lookup mcp                     # ローカル MCP サーバー (stdio)
```

- 入力種別(IP / ASN / ドメイン)は自動判別。`--type` で明示可能
- 3 種のいずれとしても解釈できない入力は**ネットワーク送信前に拒否**
  (プロトコルインジェクションとレート枠浪費を防ぐ安全機構)
- 結果はローカルにキャッシュ(デフォルト TTL 24 時間)。`--refresh` で無視
- `--raw` で生 WHOIS テキスト / RDAP レスポンスを同梱
- 出力には `source`(`rdap` | `whois`)を明示。IDN クエリでは punycode 形の
  `query_ascii` を併記

**取得できる情報について:** GDPR(2018)以降、registrant の個人情報の大半は
"REDACTED FOR PRIVACY" で秘匿されています。安定して取得できるのは registrar、
各種日付、ネームサーバー、ステータス、および IP/ASN クエリでは RIR・
ネットワーク名・割り当て範囲・abuse 連絡先です。

## ビルドとテスト

```bash
make build   # → dist/whois-lookup   (`go build` 直接実行は禁止)
make test    # go test -race -cover ./...
```

Go 1.25+。外部依存なし。

## 設定

任意 — デフォルトのままで動作します。キャッシュ TTL・キャッシュディレクトリ・
bootstrap URL・タイムアウトを変えたい場合は
[config.example.toml](config.example.toml) を
`~/.config/whois-lookup/config.toml` にコピーしてください。credential は
存在しません。

## データソース

- IANA RDAP bootstrap レジストリ: <https://data.iana.org/rdap/>(公開)
- 各 RIR・レジストリ・レジストラの RDAP エンドポイント(公開)
- `whois.iana.org` を起点とする port 43 WHOIS referral チェーン(公開、
  フォールバック専用)

## ライセンス

MIT — [LICENSE](LICENSE) を参照。
