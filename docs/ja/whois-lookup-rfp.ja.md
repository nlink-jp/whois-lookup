# RFP: whois-lookup

> Generated: 2026-07-16
> Status: Draft

## 1. Problem Statement

インシデントレスポンスや OSINT 調査の過程で、ドメイン・IP アドレス・AS 番号の
登録情報(registrar、登録/更新/失効日、ネームサーバー、abuse 連絡先)を確認したい
場面は頻繁にある。既存の `whois` コマンドは出力がレジストリごとにバラバラで
機械可読性がなく、商用 WHOIS API は credential と費用を要求する。

whois-lookup は、公式かつ無料の RDAP (RFC 7480〜) を第一線とし、RDAP 未対応の
ccTLD のみ port 43 WHOIS にフォールバックすることで、**credential ゼロ・
コマンド一発**で構造化された登録情報を返す CLI 兼 MCP サーバーである。
対象ユーザーは運営者自身、および MCP 経由で調査を行う Claude。

姉妹品との棲み分け: asn-lookup が「この IP はどの AS か」(オフライン・高速)を
答えるのに対し、whois-lookup は「その割り当て・登録の詳細と連絡先」
(オンライン・詳細)を答える。

## 2. Functional Specification

### Commands / API Surface

CLI:

- `whois-lookup lookup <ip|domain|ASn>` — 入力を自動判別してルックアップ
  - `--type ip|domain|asn` — 判別の明示指定
  - `--json` — JSON 出力(デフォルトは human-readable テキスト)
  - `--raw` — 生 WHOIS テキスト / 生 RDAP レスポンスを結果に同梱
  - `--refresh` — キャッシュを無視して再取得
  - `--timeout <dur>` — ネットワークタイムアウト
- `whois-lookup cache status` — キャッシュ統計(件数、bootstrap の鮮度)
- `whois-lookup cache clear` — クエリキャッシュの削除
- `whois-lookup mcp` — MCP サーバー起動(stdio)
- `whois-lookup version`

MCP ツール(data-toolbox-mcp 骨格を移植):

- `lookup` — CLI の lookup と同一ロジック(query, type?, raw?, refresh?)
- `cache_status` — キャッシュ状態
- `get_usage` — ツールリファレンスとエラー回復表

### Input / Output

入力判別: `netip.ParseAddr` が通れば IP(v4/v6)、`^AS\d+$`(大文字小文字不問)
なら ASN。それ以外は**ドメイン構文検証を通過した場合のみ**ドメインとして扱い、
どれにも該当しない入力はネットワーク送信前にエラーで拒否する(安全機構)。

ドメイン構文検証(RFC 準拠ホスト名チェック):

- 正規化: 前後空白 trim、小文字化、末尾ドット除去
- 全体 253 文字以下、ラベルは 1〜63 文字
- ラベルは LDH 形式(英数字とハイフンのみ、ハイフンの先頭/末尾は不可)
- 最低 1 つのドットを含む(TLD 単独は `--type domain` 明示時のみ許可)
- 制御文字・空白・CRLF を含む入力は即拒否 — port 43 は「クエリ + CRLF」の
  生プロトコルのため、CRLF 混入はプロトコルインジェクションに直結する
- IDN(日本語ドメイン等)対応: 非 ASCII を含むラベルは検証前に自前 punycode
  実装(RFC 3492、依存ゼロ)で A-label(`xn--`)へ変換し、変換後のラベルに
  LDH 検証を適用する。punycode 済み入力もそのまま受理。キャッシュキーと
  クエリには A-label 形を用いる(`日本語.jp` と `xn--wgv71a119e.jp` は同一
  キャッシュエントリ)。Phase 1 時点では A-label のみ受理し、U-label 変換は
  Phase 2 で実装

検証失敗時の挙動: ネットワークへは一切送信せず、CLI は非ゼロ終了 + 判別失敗
理由を明示。MCP は構造化ツールエラー `{code: "invalid_input", message, details}`
を返す。これによりレート制限の浪費とキャッシュキー汚染も防ぐ。

出力 JSON スキーマ(主要フィールド):

```json
{
  "query": "日本語.jp",
  "query_ascii": "xn--wgv71a119e.jp",
  "type": "domain",
  "source": "rdap",
  "registrar": "...",
  "created": "...", "updated": "...", "expires": "...",
  "nameservers": ["..."],
  "status": ["..."],
  "abuse_contact": {"name": "...", "email": "..."},
  "raw": "(--raw 指定時のみ)"
}
```

- `source` は `rdap` | `whois` を必ず明示する
- IP/ASN クエリでは registrar の代わりに RIR・ネットワーク名・割り当て範囲・
  abuse 連絡先(RDAP vCard 由来)を返す
- WHOIS フォールバック時は raw テキストを一次成果とし、key: value 形式の
  緩い抽出をベストエフォートで付与する(本格パースはしない)

### 解決フロー

1. IANA RDAP bootstrap(`dns.json` / `ipv4.json` / `ipv6.json` / `asn.json`)を
   ETag 条件付き GET でローカルキャッシュし、エンドポイントを解決
2. RDAP クエリ(HTTPS + JSON)
3. TLD が RDAP 未対応(bootstrap に無い / 404)の場合のみ port 43 WHOIS へ
   フォールバック: `whois.iana.org` → `refer:` → レジストリ →
   (thin registry の場合)`Registrar WHOIS Server:` → レジストラ

### Configuration

- sectioned TOML: `~/.config/whois-lookup/config.toml`(既存 config 規約準拠)
- 設定項目: クエリキャッシュ TTL(デフォルト 24h)、bootstrap 再検証間隔、
  タイムアウト、キャッシュディレクトリ
- env var で上書き可能(`WHOIS_LOOKUP_*`)
- キャッシュ実体: `~/.cache/whois-lookup/`

### External Dependencies

- Go 外部ライブラリ依存: **ゼロ**(`net/http`, `net`, `net/netip`,
  `encoding/json` のみ)
- ネットワーク先: IANA(bootstrap / port 43 referral 起点)、各 RIR・レジストリ・
  レジストラの RDAP / WHOIS エンドポイント。すべて認証不要の公開サービス

## 3. Design Decisions

- **RDAP-first**: 構造化 JSON で返り、ICANN が gTLD に提供を義務化(2019〜)、
  5 RIR(ARIN/RIPE/APNIC/LACNIC/AFRINIC)が完全対応。パース地獄の生 WHOIS を
  主経路にしない
- **port 43 はフォールバック専用**: .jp を含む多くの ccTLD が RDAP 未提供の
  ためにのみ残す。プロトコル実装は `net` だけで ~30 行
- **credential ゼロ**: tor-exit-lookup / icloud-relay-lookup と同じ運用感。
  商用 WHOIS API(WhoisXML 等)は RDAP で無料・公式に取れるものに費用を払う
  ことになるため不採用
- **外部 whois ライブラリ不採用**: 依存ゼロ方針に反し、実装量も自前と大差ない
- **IDN は簡易 IDNA + 自前 punycode**: `x/net/idna` を入れず、RFC 3492
  punycode エンコーダーを自前実装(~150 行)。マッピングは小文字化のみの
  簡易版とし、UTS#46 完全マッピング・bidi 規則・contextual 規則は
  スコープ外(README に「入力は NFC 正規化済みを前提」と制約を明記)。
  出力 JSON には入力原文に加え `query_ascii`(A-label 形)を含める
- **キャッシュ構造は abuse-lookup の per-query TTL 方式を移植**、bootstrap の
  ETag 条件付き GET は icloud-relay-lookup のパターンを移植
- **スコープ外**: 商用 API 連携、生 WHOIS の本格パーサー、WHOIS 履歴、
  一括/バルククエリ最適化、reverse whois

## 4. Development Plan

### Phase 1: Core

- 入力判別 + 構文検証ゲート(IP / ASN / ドメイン; 不正入力は送信前拒否)
- IANA bootstrap 取得 + ETag 条件付き GET キャッシュ
- RDAP クライアント(domain / ip / autnum)
- per-query TTL キャッシュ
- `lookup` サブコマンド + `--json`
- テスト: HTTP クライアント注入によるモックで全経路をカバー

### Phase 2: Features

- port 43 WHOIS フォールバック + referral 追跡(iana → registry → registrar)
- IDN 対応: 自前 punycode(RFC 3492)エンコーダーで U-label → A-label 変換
  (RFC 付録のサンプルベクター + 日本語ドメイン実例でテスト)
- `--raw` / 緩い key:value 抽出
- `cache status|clear` サブコマンド
- MCP サーバー(`lookup` / `cache_status` / `get_usage`)

### Phase 3: Release

- README.md / README.ja.md / CHANGELOG.md / AGENTS.md
- `make build-all`(4 platform)+ macOS 署名・notarize
- リリース 12 ステップ(zip 個別 upload)
- cybersecurity-series submodule 追加、org profile、web site catalog、
  homebrew-tap、check-org.sh

Phase 1 と Phase 2 は独立してレビュー可能。

## 5. Required API Scopes / Permissions

None。全データソース(IANA / RIR / レジストリ / レジストラの RDAP・WHOIS)は
認証不要の公開エンドポイント。

## 6. Series Placement

Series: **cybersecurity-series**

Reason: abuse-lookup / tor-exit-lookup / icloud-relay-lookup と同じ
「調査系 lookup 姉妹品」の棚。主用途が IR・OSINT 調査であるため、汎用
ユーティリティ(util-series)ではなくセキュリティツール群に置く。

## 7. External Platform Constraints

- **レジストリのレート制限**: 特に port 43(Verisign 等)は厳しい。TTL
  キャッシュ(デフォルト 24h)は礼儀としても必須。リトライは控えめに設計
- **GDPR redaction**: 2018 年以降、registrant 個人情報の大半は
  "REDACTED FOR PRIVACY"。取得できるのは registrar / 各種日付 /
  ネームサーバー / ステータス / abuse 連絡先が中心である旨を README に明記
- **ccTLD の RDAP 未対応**: .jp 含む多数。フォールバック経路が必須機能
- **IANA bootstrap は低頻度更新**: ETag 条件付き GET が有効に働く
- **RDAP レスポンスの方言**: レジストリ実装によりオプションフィールドの
  有無が揺れる。デコードは寛容に、出力スキーマ側で正規化する

---

## Discussion Log

- 2026-07-16: 初回相談。実装方式として (a) 生 WHOIS 主体、(b) 外部 whois
  ライブラリ、(c) 商用 API、(d) RDAP-first + WHOIS フォールバックを比較し、
  (d) を採択。理由: 構造化出力・credential ゼロ・外部依存ゼロを同時に満たす
  唯一の構成のため
- シリーズ配置は util-series(asn-lookup と同棚)案もあったが、主用途が
  IR/OSINT 調査であることから cybersecurity-series に決定
- ASN クエリ(RDAP autnum)は入力判別の追加と RDAP 実装の共通化で安価に
  実現できるため v0.1 スコープに含める。asn-lookup との棲み分けは
  「帰属(オフライン)」vs「登録情報・連絡先(オンライン)」で明確
- CLI 体裁は対象別サブコマンド(domain/ip/asn)案を退け、`lookup` 単一 +
  自動判別を採択。MCP ツールも同一ロジックの `lookup` 単一とし、CLI/MCP の
  挙動を揃える
- キャッシュ戦略: abuse-lookup の per-query TTL + icloud-relay-lookup の
  ETag 条件付き GET を組み合わせるハイブリッド。WHOIS データは変化が遅い
  ため TTL デフォルトは 24h
- 2026-07-16(レビュー指摘): 当初案の「IP でも ASN でもなければドメイン扱い」
  を改め、ドメイン構文検証ゲートを追加。IP/ASN/ドメインのいずれとしても
  解釈できない入力は送信前にエラー拒否する。理由: port 43 への CRLF
  プロトコルインジェクション防止、レート制限の浪費防止、キャッシュキー
  汚染防止。IDN の U-label 変換は依存ゼロ方針との兼ね合いで当初 v0.1 外とした
- 2026-07-16(追加判断): IDN 対応を計画に組み込み。`x/net/idna` は使わず
  RFC 3492 punycode を自前実装(~150 行、依存ゼロ維持)して Phase 2 で実装。
  簡易 IDNA(小文字化のみ、UTS#46/bidi はスコープ外)とし、.jp の日本語
  ドメイン調査を主ユースケースとして想定。キャッシュキーは A-label 形で統一
