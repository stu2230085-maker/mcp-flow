# Pull Request レビューレポート (PR #5〜#9)

- **レビュー日**: 2026-11-25
- **対象リポジトリ**: `stu2230085-maker/mcp-flow` (`base: main @ 465adde`)
- **準拠ガイドライン**: [AGENTS.md](../../AGENTS.md) / [CLAUDE.md](../../CLAUDE.md) / [docs/design.md](../design.md)

---

## 全体サマリー

| PR | ブランチ | タイトル | 単体テスト | `mcp-flow evaluate` | 判定 | 要約 |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **#5** | `feat/1-wrap-config` | feat(config): add wrap-config CLI | **FAIL** (`SyntaxError`) | **FAIL** (`SyntaxError`) | **Request Changes** | 全3ファイルの1行目にシェルエラー文字列が混入し起動不能。グローバル `--db` 引数との競合・非アトミック書き込みも要修正 |
| **#6** | `feat/2-otel-mcptape-interop` | feat(interop): Add OpenTelemetry & mcptape trace import/export | 13 tests OK | PASS (`NegFP=0`) | **Request Changes** | `import_trace_jsonl` の `server_id` がセッション分離されず、実プロキシ出力の再インポートで `servers` PK衝突およびロール判定ルール不一致が発生 |
| **#7** | `docs/readme-cli-reference` | docs(readme): expand CLI reference, landscape comparison, and rules guide | 10 tests OK | PASS (`NegFP=0`) | **Request Changes** | `detectors.py` と異なるラベル名（`secret:aws_access_key` → 実装は `secret:aws_key`）や未実装パターンを記載 |
| **#8** | `feat/4-proxy-batch-benchmark` | perf(proxy): High-throughput benchmark & SQLite batch transaction optimization (#4) | 15 tests OK | PASS (`NegFP=0`) | **Approve** *(軽微なコメント)* | 30.4 MiB/s・`byte_exact=True`・全不変条件クリア。大ペイロード連投時のバッチ総バイト上限追加等を推奨 |
| **#9** | `feat/3-cross-session-taint` | feat(persistence): Cross-session persistent taint tracking via content fingerprint registry | 17 tests OK | PASS (`NegFP=0`) | **Request Changes** | `--source-label "secret:*"` でクロスセッション経路がヒットしない不具合、既存 `calls` 存在時に `report --cross-session` が無視される不具合、`clear_derived_data` の孤立ID、Call継承ラベルによる誤検出リスク |

---

## 1. PR #5 — `feat(config): add wrap-config CLI` (Closes #1)

- **判定**: **Request Changes**
- **検証結果**: `unittest` / `evaluate` ともに `SyntaxError` により実行失敗

### アーキテクチャ不変条件チェックリスト
- [x] **不変条件1 (無改変中継)**: `proxy/` への変更なし
- [x] **不変条件2 (再計算可能性)**: `messages` への破壊的操作なし
- [ ] **不変条件3 (機密保護)**: `.bak` は `0600` で作成されているが、本体上書きが非アトミックで権限維持保証がない
- [ ] **不変条件4 (誤検出抑制)**: `SyntaxError` により `evaluate` 実行不可
- [x] **不変条件5 (ゼロ外部依存)**: 標準ライブラリのみ使用
- [x] **不変条件6 (マイグレーション)**: スキーマ変更なし
- [x] **不変条件7 (因果注記)**: レポート・グラフ出力への変更なし

### 指摘事項

1. **[Blocker] 全変更ファイルの1行目に不正なエラー出力が混入しており `SyntaxError` で動作不能**
   - **箇所**: `src/mcp_flow/cli.py:1`, `src/mcp_flow/config_wrapper.py:1`, `tests/test_config_wrapper.py:1`
   - **内容**: 3ファイルすべての先頭行に `Failed to connect to user scope bus via local transport: Operation not permitted (consider using --machine=<user>@.host --user to connect to bus of other user)` がコミットされており、`mcp-flow` 全体が起動不能になっています。
   - **修正案**: 3ファイルの先頭1行目を削除し、`unittest` および `mcp-flow evaluate` が通ることを確認してください。

2. **[Major] グローバル `--db` オプションと `wrap-config --db` の競合**
   - **箇所**: `src/mcp_flow/cli.py:55, 133, 173`
   - **内容**: 他サブコマンドと同じく `mcp-flow --db /custom/trace.db wrap-config config.json` と指定した場合、`p_wrap.add_argument("--db", dest="config_db", default="mcp_flow.db")` のデフォルト値が優先され、指定した `/custom/trace.db` が黙って無視されます。また MCP クライアント（Claude Desktop / Cursor 等）は起動時のカレントディレクトリが不定なため、相対パス `"mcp_flow.db"` のまま書き込むと起動失敗や意図しない場所へのDB生成を招きます。
   - **修正案**: `p_wrap` 側は `default=None` とし、`db_path = args.config_db if args.config_db is not None else args.db` にフォールバックさせたうえで、必要に応じて `Path(db_path).expanduser().resolve()` 等で絶対パス化することを推奨します。

3. **[Major] 設定ファイルの非アトミック上書きと `.bak` の鮮度不整合**
   - **箇所**: `src/mcp_flow/cli.py:183-189`
   - **内容**:
     - `path.write_text(...)` は直接 truncate 上書きするため、書き込み中断時のファイル破損リスクがあり、`env` にAPIキー等を含む設定ファイルのパーミッションを明示的に保護していません（同一ディレクトリの一時ファイル作成＋権限引き継ぎ/`0600` 設定＋`os.replace` 推奨）。
     - `if not backup.exists():` により、一度 `.bak` が作られた後は設定編集後に再ラップしても古い `.bak` が更新されないまま `Updated ...; backup: ...bak` と出力されます。

4. **[Minor] `_is_wrapped` の判定範囲**
   - **箇所**: `src/mcp_flow/config_wrapper.py:10-21`
   - **内容**: `"proxy" in args` や `args.index("-m")` が `"--"` 以降（ラップ対象サーバー自身の引数）も走査しています。`marker = args.index("--")` より前の `args[:marker]` のみを検査対象にしてください。

---

## 2. PR #6 — `feat(interop): Add OpenTelemetry & mcptape trace import/export` (Closes #2)

- **判定**: **Request Changes**
- **検証結果**: `unittest` 13件 PASS / `evaluate` 全ステージ PASS (`NegFP == 0`)

### アーキテクチャ不変条件チェックリスト
- [x] **不変条件1 (無改変中継)**: `proxy/` への変更なし
- [x] **不変条件2 (再計算可能性)**: `messages` への追記のみ（ただし `servers` 登録に不整合あり）
- [x] **不変条件3 (機密保護)**: OTel エクスポートに断片平文を含めないことをテスト済み
- [x] **不変条件4 (誤検出抑制)**: `NegFP == 0` 維持
- [x] **不変条件5 (ゼロ外部依存)**: 標準ライブラリのみ使用（`opentelemetry` パッケージ非依存）
- [x] **不変条件6 (マイグレーション)**: スキーマ変更なし
- [x] **不変条件7 (因果注記)**: OTel `resource.attributes["mcp.observation.disclaimer"]` に `OBSERVATION_DISCLAIMER` を付与

### 指摘事項

1. **[Major] `import_trace_jsonl` の `server_id` がセッション分離されず、実プロキシ出力の再インポートでロール判定・サーバーマップが壊れる**
   - **箇所**: `src/mcp_flow/interop/trace_io.py:182-194`（関連: `src/mcp_flow/store/db.py:31-37, 258-279, 639-660`）
   - **内容**:
     - `mcp-flow proxy` は `server_id = f"{session_id}:{server_name}"`（例: `"orig-session:docs"`）で記録し、`export_messages_jsonl` は `"server_id"` のみを出力します（`"server"` や `"server_name"` は含まれません）。
     - これを `mcp-flow import trace.jsonl --session reimported-session` で取り込むと、`server_name` が `"docs"` ではなく `"orig-session:docs"` となり、`LabelRuleEngine` の `docs*` / `vault*` / `mail*` 等のサーバー名グロブルールに一切マッチしなくなります。
     - さらに `servers.id` はDB全体の `PRIMARY KEY` であり、`register_server` の `ON CONFLICT(id)` は `session_id` を更新しないため、元セッション側の `servers.name` を上書き汚染したうえ、`get_server_map("reimported-session")` が空辞書になります（`mcptape` トレースを同一DBの複数セッションへインポートした場合も同様に `server_id="vault"` が衝突します）。
   - **修正案**: `rec.get("server") or rec.get("server_name")` が無い場合、`raw_server_id` から元レコードの `f"{rec_session_id}:"` プレフィックス（または `":"` 区切り）を剥がして論理 `server_name` を復元し、登録・保存時の `server_id` は常に `f"{resolved_session}:{server_name}"` に名前空間分離してください。あわせて `register_server` を通した実プロキシ相当データでのラウンドトリップテストを追加してください。

2. **[Minor] `_DIRECTION_ALIASES` における `"in"` / `"out"` と `"inbound"` / `"outbound"` の逆転**
   - **箇所**: `src/mcp_flow/interop/trace_io.py:21-36`
   - **内容**: `"outbound": "c2s"` / `"inbound": "s2c"` に対し、`"in": "c2s"` / `"out": "s2c"` と視点が逆転したエイリアスが共存しています。曖昧な `"in"` / `"out"` を削除して JSON-RPC メッセージ構造（`method` vs `result`/`error`）からの推論に委ねるか、ドキュメントで明記することを推奨します。

3. **[Minor] OTel 属性の `None` 値・ストリーム読み込み・トランザクション原子性**
   - **箇所**: `src/mcp_flow/interop/trace_io.py:139-205, 267`
   - **内容**:
     - 未応答の呼び出しで `node.res_seq` が `None` の際、`"mcp.res_seq": null` が出力されます（OTel 仕様では `null` 属性値を避けキー自体を省略するのが望ましいです）。
     - `path.read_text().splitlines()` による一括メモリ展開および1件ごとの `append_message` コミットになっているため、途中行の不正データでエラー終了した際に前半行だけがセッションに残ります。全行検証後の単一トランザクション投入を推奨します。

---

## 3. PR #7 — `docs(readme): expand CLI reference, landscape comparison, and rules guide`

- **判定**: **Request Changes**
- **検証結果**: `unittest` 10件 PASS / `evaluate` 全ステージ PASS (`NegFP == 0`)

### 指摘事項

1. **[Major] Built-In Content Detectors のラベル名・検出パターンが `src/mcp_flow/labels/detectors.py` の実装と不一致**
   - **箇所**: `README.md:400-407`（実装: `src/mcp_flow/labels/detectors.py:16-57`）
   - **内容**:
     - `secret:aws_access_key` と記載されていますが、実装が出力するラベルは **`secret:aws_key`** です（読者が `--source-label "secret:aws_access_key"` で検索すると結果が0件になります）。
     - `secret:api_key` の例として `rk-...` が挙げられていますが、実装の正規表現 `\bsk-[A-Za-z0-9_-]{16,}\b` は `sk-...` のみにマッチします。
     - `confidential:doc` の例として `INTERNAL ONLY`, `DO NOT DISTRIBUTE`, `取扱注意` が挙げられていますが、実装の正規表現 `(?i)\b(?:CONFIDENTIAL|INTERNAL_ONLY|SECRET_TOKEN)\b|社外秘|機密文書|極秘` とは一致しません。
   - **修正案**: `detectors.py` の定義と完全一致するよう記載を修正してください。

2. **[Minor] Redaction プレースホルダ表記と並行PRマージ後のサブコマンド一覧同期**
   - **箇所**: `README.md:18, 183, 209`
   - **内容**:
     - 209行目で `--redact-pattern` の置換文字列を `[REDACTED]` と説明していますが、実装（`RedactionPolicy`）は `[REDACTED:PATTERN_0]` 形式です。
     - 見出しが `CLI Reference (All 8 Subcommands)` と固定されているため、PR #5 (`wrap-config`)・PR #6 (`import`, `export --format otel`)・PR #9 (`--persist-labels`, `--cross-session`) のマージ後にサブコマンド数およびオプション表の更新が必要です。

---

## 4. PR #8 — `perf(proxy): High-throughput benchmark & SQLite batch transaction optimization (#4)` (Closes #4)

- **判定**: **Approve** *(軽微な改善提案あり)*
- **検証結果**:
  - `unittest` 15件 PASS / `evaluate` 全ステージ PASS (`NegFP == 0`)
  - ベンチマーク実測:
    - Large Payload (3 x 1.00 MiB): `throughput=30.4 MiB/s`, `recorded=6/6`, `byte_exact=True`
    - Burst Calls (250 calls, `batch_size=64`): `rate=1954 calls/s`, `recorded=500/500`, `byte_exact=True`

### アーキテクチャ不変条件チェックリスト
- [x] **不変条件1 (無改変中継)**: 1MiB超フレーム・250連投ともにバイト単位完全一致（`byte_exact=True`）かつログ例外時の中継継続を確認
- [x] **不変条件2 (再計算可能性)**: `messages` 追記専用を維持し `derive_calls` 等がそのまま動作
- [x] **不変条件3 (機密保護)**: `append_messages_batch` でも `RedactionPolicy` と `0600` 権限を維持
- [x] **不変条件4 (誤検出抑制)**: `NegFP == 0` 維持
- [x] **不変条件5 (ゼロ外部依存)**: 標準ライブラリのみ使用
- [x] **不変条件6 (マイグレーション)**: `SCHEMA_V1_SQL` 変更なし
- [x] **不変条件7 (因果注記)**: 出力系への変更なし

### コメント（任意対応・フォローアップ可）

1. **[Minor] 大容量フレーム連投時の1バッチあたり総バイト上限**
   - **箇所**: `src/mcp_flow/proxy/stdio_proxy.py:48-56`
   - **内容**: `batch_size=64` の件数上限のみのため、数MiB規模のレスポンスが連続でキューに積まれた場合、1バッチ内でデコード前後・Redaction後のコピーを含めメモリ使用量が膨らむ可能性があります。`max_batch_bytes`（例: 4MiB）を超えた時点でもバッチを確定させるとメモリ上限が安定します。

2. **[Minor] `_write_all` の `n is None or n == 0` 時の扱いとテストの時間閾値**
   - **箇所**: `src/mcp_flow/proxy/stdio_proxy.py:24-26`, `tests/test_proxy_large_payload_and_load.py:173, 206, 230`
   - **内容**: 非ブロッキングストリーム等で `dst.write()` が `None` / `0` を返した際に `break` すると末尾バイトが欠落し得るため、`BrokenPipeError` 等の送出またはリトライが安全です。また共有 GitHub Actions ランナーでの負荷変動を考慮し、`assertLess(elapsed, 3.0)` は `5.0` 秒程度に余裕を持たせるとフレーク防止になります。

---

## 5. PR #9 — `feat(persistence): Cross-session persistent taint tracking via content fingerprint registry` (Closes #3)

- **判定**: **Request Changes**
- **検証結果**: `unittest` 17件 PASS / `evaluate` 全ステージ PASS (`NegFP == 0`)

### アーキテクチャ不変条件チェックリスト
- [x] **不変条件1 (無改変中継)**: `proxy/` への変更なし
- [ ] **不変条件2 (再計算可能性)**: 通常 `analyze` 再実行時に `clear_derived_data` が `persistent_fingerprints` の旧 `call_id` / `frag_id` を更新・削除せず孤立IDが残る
- [x] **不変条件3 (機密保護)**: `persistent_fingerprints` はハッシュ・長さ・ラベルのみ保存（平文保存なし）、`0600` 権限維持、`serve-mcp` の `expose_text=False` 非開示維持
- [ ] **不変条件4 (誤検出抑制)**: 合成ベンチマークは `NegFP == 0` だが、Call単位 `confidential:*` ラベル継承時に短い定型値（`"production"` 等）が `score=1.0` で永続登録される構造的リスクあり
- [x] **不変条件5 (ゼロ外部依存)**: 標準ライブラリのみ使用
- [x] **不変条件6 (マイグレーション)**: `SCHEMA_V1_SQL` 無変更、`MIGRATIONS` に V2 を追記し V1→V2 アップグレードをテスト済み
- [x] **不変条件7 (因果注記)**: CLI レポートおよび MCP サーバー応答で `OBSERVATION_DISCLAIMER` を維持

### 指摘事項

1. **[Major] `--source-label "secret:*"` 等のグロブフィルタでクロスセッション経路が検出されない**
   - **箇所**: `src/mcp_flow/graph/paths.py:33-40, 61-74`
   - **内容**:
     - クロスセッション一致ラベルは `"cross_session:<origin_session_id>:<label>"` 形式で付与されるため、`_matches_source_criteria` で `source_label="secret:*"` や `"confidential:*"` を指定すると `fnmatchcase("cross_session:session_a:secret:api_key", "secret:*")` も部分一致も `False` となり、経路が一切検出されません（`mcp-flow report` や MCP ツール `find_paths` の代表的な使い方が機能しません）。
     - また 61〜74行目で `start_node` が別ラベル（例: `pii:*`）でソース判定を通過した場合、`cross_session_labels` を `source_label` で絞り込まずに出力してしまいます。さらに `bottleneck_score=1.0` がハードコードされており、`norm_hash` マッチ時の `0.95` や `min_score` 閾値が反映されていません。
   - **修正案**: `cross_session:<sid>:` プレフィックスを除去した元ラベルに対しても `source_label` のグロブ判定を行い、該当する `cross_session_labels` のみを抽出したうえで、実際のマッチスコアと `min_score` を反映してください。

2. **[Major] 解析済みセッションに対する `mcp-flow report <session> --cross-session` が黙って無視される**
   - **箇所**: `src/mcp_flow/cli.py:212-219`
   - **内容**: `if args.recompute or not store.get_calls(args.session):` の分岐内でのみ `cross_session=args.cross_session` が実行されるため、事前に通常の `mcp-flow analyze sess_b` を実行済みだと、`mcp-flow report sess_b --cross-session` を実行してもクロスセッション照合が走らず 0 件になります。
   - **修正案**: `args.cross_session` 指定時は未照合であれば `match_cross_session_taint(store, args.session)` を実行する（または再解析を行う）ようにしてください。

3. **[Major] `clear_derived_data` 実行時の `persistent_fingerprints` の孤立ID残存**
   - **箇所**: `src/mcp_flow/store/db.py:370-410`
   - **内容**: `--persist-labels` 実行後に通常の `mcp-flow analyze <session>`（ルール変更後など）を実行すると、`calls` / `fragments` の主キーが再採番される一方で `persistent_fingerprints` がクリアされないため、`origin_call_id` / `origin_frag_id` が削除済み行を指す孤立参照になり、撤回されたはずのラベルも残り続けます。
   - **修正案**: `clear_derived_data` 内で対象セッション由来の `persistent_fingerprints` もクリアする（または `analyze` の再計算仕様を整理する）ようにしてください。

4. **[Major] Call単位 `confidential:*` ラベル継承による汎用文字列での誤検出リスク**
   - **箇所**: `src/mcp_flow/match/cross_session.py:139-163`
   - **内容**: `docs.read_file` や `db.query` のように Call 全体に `confidential:*` が付与されるツールでは、レスポンス内の全 `out` 葉断片（6文字以上・エントロピー1.5以上、例: `"production"`, `"completed"`, `"us-east-1"` 等）まで `persistent_fingerprints` に登録され、後続セッションのシンク引数に同じ一般語が含まれただけで `score=1.0` の機密漏洩になります。
   - **修正案**: Call から継承したラベルについては断片の最小長・エントロピー基準を引き上げる（例: `min_len >= 16` 等）、あるいは複数セッションに頻出するハッシュの重み減衰を導入することを推奨します。

---

## マージ互換性・推奨マージ順序

- **DBマイグレーション競合**: なし（`MIGRATIONS` を変更するのは PR #9 の V2 のみ）。
- **統合マージ検証**: `SyntaxError` のある PR #5 を除く4本（**#6 + #7 + #8 + #9**）を統合マージしてテストを実行し、コンフリクトなし・**25 tests OK**・`mcp-flow evaluate` 全ステージ **`NegFP == 0`** を確認済み。
- **推奨マージ順序**:
  1. **PR #8**（現状のままマージ可能、または Minor 反映後マージ）
  2. **PR #6 / PR #9 / PR #5**（各 Request Changes 指摘の修正・再検証後に順次 Squash Merge）
  3. **PR #7**（`detectors.py` ラベル名の修正に加え、上記PRで追加された `wrap-config` / `import` / `export --format otel` / `--persist-labels` / `--cross-session` を CLI リファレンスに反映してマージ）
