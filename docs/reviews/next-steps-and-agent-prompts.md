# 今後の進め方ランブック ＆ Neon / Hydrogen エージェント指示プロンプト集

## モデル（エージェント）役割分担方針

**Carbon** のクォータを全体設計・オーケストレーション・最終監査レビューに温存するため、実装修正はタスク難度に応じて **Neon** と **Hydrogen** に振り分けます。

| PR | ブランチ | 推奨担当モデル | サブエージェント指定 | 選定理由 |
| :--- | :--- | :--- | :--- | :--- |
| **#8** | `feat/4-proxy-batch-benchmark` | *(完了 / Squash Merge)* | — | 全15テスト・ベンチマーク・7不変条件クリア済みのため先行マージ |
| **#9** | `feat/3-cross-session-taint` | **Gemini 4 Neon** | `pro` | `paths.py`・`cross_session.py`・`db.py`・`cli.py` をまたぐ複合ロジックと誤検出閾値設計が必要 |
| **#6** | `feat/2-otel-mcptape-interop` | **Gemini 4 Neon** | `pro` | `servers` テーブル主キー制約を踏まえたセッション名前空間分離・トランザクション設計が必要 |
| **#5** | `feat/1-wrap-config` | **Gemini 4 Hydrogen** | `flash` | 1行目ゴミ削除・`--db` フォールバック・アトミック保存・`_is_wrapped` スライスと修正箇所が明確 |
| **#7** | `docs/readme-cli-reference` | **Gemini 4 Hydrogen** | `flash` | `README.md` 単一ファイルの `detectors.py` ラベル名整合および最新 CLI オプション表の同期 |

---

## 各 PR 担当エージェントへの指示プロンプト

### 1. PR #5 向けプロンプト（担当：**Hydrogen** / `feat/1-wrap-config`）

```markdown
PR #5 (`feat/1-wrap-config`) のレビュー指摘事項を修正してください。作業前に `AGENTS.md` を確認し、最新の `origin/main` を取り込んでください。
対象ファイル（`src/mcp_flow/cli.py`, `src/mcp_flow/config_wrapper.py`, `tests/test_config_wrapper.py`）以外は変更しないでください。

### 必須修正項目
1. **[Blocker] 先頭1行目の不正文字列による `SyntaxError` の解消**
   - `src/mcp_flow/cli.py:1`、`src/mcp_flow/config_wrapper.py:1`、`tests/test_config_wrapper.py:1` の1行目に混入している `Failed to connect to user scope bus via local transport: ...` を削除してください。
2. **[Major] グローバル `--db` オプションと `wrap-config --db` の競合修正 (`src/mcp_flow/cli.py`)**
   - `p_wrap` 側の `--db` (`dest="config_db"`) は `default=None` に変更し、`db_path = args.config_db if args.config_db is not None else args.db` でサブコマンド前後どちらの `--db` 指定も反映されるようにしてください。
3. **[Major] 設定ファイルのアトミック更新と `.bak` 更新整合性 (`src/mcp_flow/cli.py`)**
   - `path.write_text(...)` の直接上書きをやめ、同一ディレクトリ内の一時ファイル作成（元ファイルのパーミッション維持、取得不可時は `0o600`）＋ `os.replace` でアトミックに置換してください。
   - `.bak` も設定内容に変更が生じて書き換える際は、最新の変更前バイト列が `0o600` 権限で保存されるようアトミックに更新してください。
4. **[Minor] `_is_wrapped` の判定範囲の厳密化 (`src/mcp_flow/config_wrapper.py`)**
   - `"--"` の位置 `marker = args.index("--")` より前の `wrapper_args = args[:marker]` の範囲内だけで `-m mcp_flow` と `proxy` を判定してください。
5. **テスト追加 (`tests/test_config_wrapper.py`)**
   - `mcp-flow --db custom.db wrap-config ...` が反映されるテスト、および元サーバー引数（`"--"` 以降）に `"proxy"` / `"-m"` を含んでも誤判定しないテストを追加してください。

### 完了条件
- `PYTHONPATH=src:. python3 -m unittest discover -s tests -v`
- `PYTHONPATH=src:. python3 -m mcp_flow evaluate` (`NegFP == 0`)
```

---

### 2. PR #6 向けプロンプト（担当：**Neon** / `feat/2-otel-mcptape-interop`）

```markdown
PR #6 (`feat/2-otel-mcptape-interop`) のレビュー指摘事項を修正してください。作業前に `AGENTS.md` を確認し、最新の `origin/main` を取り込んでください。
対象ファイル（`src/mcp_flow/interop/`, `src/mcp_flow/cli.py`, `tests/test_interop_otel.py`）以外は変更しないでください。

### 必須修正項目
1. **[Major] `import_trace_jsonl` における `server_id` のセッション名前空間分離 (`src/mcp_flow/interop/trace_io.py`)**
   - `rec.get("server") or rec.get("server_name")` が無い場合、`raw_server_id` から元レコードの `f"{rec_session_id}:"` プレフィックス（または `":"` 区切りの後半）を剥がして純粋な論理 `server_name`（例: `"docs"`）を抽出してください。
   - インポート先への登録・メッセージ保存時の `server_id` は常に `f"{resolved_session}:{server_name}"` に名前空間分離し、`ImportResult.servers` には重複のない論理 `server_name` リストを返してください。
2. **[Minor] 方向エイリアス・OTel `None` 属性・トランザクション原子性 (`src/mcp_flow/interop/trace_io.py`)**
   - `_DIRECTION_ALIASES` から `"inbound"` / `"outbound"` と逆向きになっている曖昧な `"in"` / `"out"` を除去してください。
   - `export_otel_spans` で `node.res_seq is None` の場合は `"mcp.res_seq"` キー自体を `attributes` から省略してください。
   - `import_trace_jsonl` は全行を検証してから単一トランザクションで書き込み、途中行エラー時に半端なデータが残らないようにしてください。
3. **テスト強化 (`tests/test_interop_otel.py`)**
   - `store.register_server("orig-session:docs", "orig-session", "docs")` 形式でシードした実プロキシ相当のラウンドトリップテストと、同一 DB 内の複数セッションへ `mcptape.jsonl` を連続インポートしても衝突しないテストを追加してください。

### 完了条件
- `PYTHONPATH=src:. python3 -m unittest discover -s tests -v`
- `PYTHONPATH=src:. python3 -m mcp_flow evaluate` (`NegFP == 0`)
```

---

### 3. PR #9 向けプロンプト（担当：**Neon** / `feat/3-cross-session-taint`）

```markdown
PR #9 (`feat/3-cross-session-taint`) のレビュー指摘事項を修正してください。作業前に `AGENTS.md` を確認し、最新の `origin/main`（PR #8 マージ済み）を取り込んでください（`SCHEMA_V1_SQL` は絶対に変更せず `MIGRATIONS` V2 追記を維持）。

### 必須修正項目
1. **[Major] `--source-label` グロブ指定時のクロスセッション経路検出バグ修正 (`src/mcp_flow/graph/paths.py`)**
   - `"cross_session:<origin_session_id>:<orig_label>"` に対して `<orig_label>` 部分でも `source_label` グロブ（例: `"secret:*"`, `"confidential:*"`）がマッチするようにし、`find_hazardous_paths` の単一ノード経路でも `source_label` に合致する `cross_session_labels` のみを抽出＆`min_score` 閾値を適用してください。
2. **[Major] 解析済みセッションに対する `mcp-flow report <session> --cross-session` の有効化 (`src/mcp_flow/cli.py`)**
   - 既に `calls` が存在するセッションに対しても `--cross-session` 指定時に `match_cross_session_taint(store, args.session)` が確実に実行されるようにしてください。
3. **[Major] `clear_derived_data` 実行時の `persistent_fingerprints` 整合性 (`src/mcp_flow/store/db.py`)**
   - `clear_derived_data(session_id)` 内で `self.clear_persistent_fingerprints(session_id)` も呼び出し、再解析時に削除済み `call_id` / `frag_id` への孤立参照が残らないようにしてください。
4. **[Major] Call 単位 `confidential:*` ラベル継承による短い一般語での誤検出抑制 (`src/mcp_flow/match/cross_session.py`)**
   - 断片直接ラベル（`frag_labels`）や `_extract_secret_span_hashes` は `min_len=6` を維持しつつ、Call 継承ラベル（`call_labels` のみ由来）についてはより厳しい情報量フィルタ（`min_len=16`, `min_entropy=2.5`）を満たす断片のみ永続登録してください。
5. **テスト追加 (`tests/test_cross_session_taint.py`)**
   - `--source-label "secret:*"` での検出、解析済みセッションへの `report --cross-session`、短い一般語（`"completed"` 等）での負例誤検出ゼロを検証するテストを追加してください。

### 完了条件
- `PYTHONPATH=src:. python3 -m unittest discover -s tests -v`
- `PYTHONPATH=src:. python3 -m mcp_flow evaluate` (`NegFP == 0`)
```

---

### 4. PR #7 向けプロンプト（担当：**Hydrogen** / `docs/readme-cli-reference`）

```markdown
PR #7 (`docs/readme-cli-reference`) のレビュー指摘事項を修正してください。`README.md` 以外のファイルは変更しないでください。

1. `Built-In Content Detectors` セクションを `src/mcp_flow/labels/detectors.py` の実装と完全一致させてください：
   - `secret:aws_access_key` → `secret:aws_key`
   - `secret:api_key` から未実装の `rk-...` を削除（`sk-...` のみ）
   - `confidential:doc` の例示を `CONFIDENTIAL`, `INTERNAL_ONLY`, `SECRET_TOKEN`, `社外秘`, `機密文書`, `極秘` に修正
2. `proxy` の `--redact-pattern` の置換表記を `[REDACTED]` から実装通りの `[REDACTED:PATTERN_0]` に修正してください。
3. （PR #5 / #6 / #9 マージ後に最終同期する場合）最新の `origin/main` の `src/mcp_flow/cli.py` に合わせて全サブコマンド・オプション表を更新してください。

### 完了条件
- `PYTHONPATH=src:. python3 -m unittest discover -s tests -v`
- `PYTHONPATH=src:. python3 -m mcp_flow evaluate` (`NegFP == 0`)
```
