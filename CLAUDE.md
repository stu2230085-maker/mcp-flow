# mcp-flow — CLAUDE.md (Implementation & Opus Review Guidelines)

MCPのツール呼び出しを中継・記録し、出力が後続の入力へ流れた経路(データ依存グラフ)を推定する観測基盤。
全体設計は [docs/design.md](docs/design.md)、マルチエージェント開発・ブランチ規約は [AGENTS.md](AGENTS.md) を参照。

---

## 1. 設計原則 (絶対遵守)
- **受動的な観測のみ**: 攻撃ペイロードの送信や通信のブロックは作らない
- **ゼロ外部依存コア**: コア (`src/mcp_flow/`) は Python 3.10+ の標準ライブラリだけで動作させる。重い依存は `pyproject.toml` の `optional-dependencies` (`extras`) に分ける
- **無改変・非ブロッキング中継**: 中継するメッセージは一切改変しない。記録で遅延やブロックを起こさない
- **一次データと派生データの分離**: `messages` テーブルは追記のみ。`calls` / `fragments` / `flows` は `messages` から何度でも再計算できる派生データとする
- **観測と因果の区別**: 辺は「内容一致の観測」であり因果の証明ではない。すべての出力・レポート・API応答で `OBSERVATION_DISCLAIMER` を明記する
- **ローカル保存と権限 `0600`**: 既定でローカル保存のみ。ネットワーク送信しない。SQLite DB ファイルの権限は `0600` を強制する
- **MCPサーバーの本文非開示ガード**: 読み取り専用 MCP サーバー (`serve-mcp`) 経由の応答では、断片の本文 (`src_text` / `dst_text`) を既定で返さない（ハッシュ、長さ、JSONパス、一致範囲のみ）

---

## 2. 開発・ブランチ運用ルール
- `main` ブランチは保護されているため直接 commit/push せず、`feat/<issue番号>-<slug>` 等のトピックブランチを切って Pull Request を作成する
- マッチング手法は `src/mcp_flow/match/` に共通インターフェース (`Matcher`) で追加する（既存のマッチャーを壊さない）
- スキーマを変えるときは `src/mcp_flow/store/db.py` の `MIGRATIONS` に新しいバージョンを追加し、`SCHEMA_V1_SQL` は直接書き換えない

### 検証コマンド
```bash
# 全単体・結合テスト実行
PYTHONPATH=src:. python3 -m unittest discover -s tests -v

# 合成シナリオ精度評価 (適合率・再現率・負例誤検出率の算出)
PYTHONPATH=src:. python3 -m mcp_flow evaluate
```

---

## 3. レビューガイドライン (別チャットの Claude Opus / レビュアー向け)

Codex Cloud や他のエージェントが作成したブランチ／Pull Request をレビューする際は、以下のコマンドとチェックリストを使用してください。

### PR の取得・検証コマンド
```bash
# オープン中の PR 一覧と CI 状態の確認
gh pr list --repo stu2230085-maker/mcp-flow

# PR の差分と説明の確認
gh pr view <PR_NUMBER> --repo stu2230085-maker/mcp-flow
gh pr diff <PR_NUMBER> --repo stu2230085-maker/mcp-flow

# ローカルで PR ブランチをチェックアウトしてテスト・評価ハーネスを実行
gh pr checkout <PR_NUMBER>
PYTHONPATH=src:. python3 -m unittest discover -s tests -v
PYTHONPATH=src:. python3 -m mcp_flow evaluate
```

### Opus アーキテクチャ・セキュリティ監査チェックリスト
1. **[不変条件1: 無改変中継]** `proxy/` の変更が JSON-RPC ペイロードを1バイトでも書き換えていないか？ ログ書き込み例外時にプロキシ中継がクラッシュしないか？
2. **[不変条件2: 再計算可能性]** `messages` テーブルに対する `UPDATE` / `DELETE`（保持期間パージを除く）が混入していないか？ `mcp-flow analyze <session>` で派生テーブルが完全に再構築できるか？
3. **[不変条件3: 機密保護]** DB ファイル作成時の `0o600` 権限維持、および `ReadOnlyFlowMcpServer` (`expose_text=False` 既定) で断片の平文が漏えいしていないか？
4. **[不変条件4: 誤検出抑制]** `python3 -m mcp_flow evaluate` を実行した際、負例シナリオの誤検出 (`NegFP`) が `0` のまま維持されているか？
5. **[不変条件5: ゼロ外部依存]** `src/mcp_flow/` 内でサードパーティ製パッケージをトップレベル `import` していないか？
6. **[不変条件6: マイグレーション]** DB スキーマ変更がある場合、既存の V1 DB からマイグレーションが通るか？
7. **[不変条件7: 因果注記]** 新しい出力フォーマットやエンドポイントにも「内容一致の観測であり因果の証明ではない」旨が含まれているか？

### レビューコメント投稿・マージコマンド
```bash
# 指摘事項がある場合 (Request Changes / Comment)
gh pr review <PR_NUMBER> --repo stu2230085-maker/mcp-flow --comment --body "<レビューコメント>"

# 承認して Squash マージする場合
gh pr review <PR_NUMBER> --repo stu2230085-maker/mcp-flow --approve --body "Reviewed by Claude Opus: All architectural invariants, privacy guards, and evaluation benchmarks verified."
gh pr merge <PR_NUMBER> --repo stu2230085-maker/mcp-flow --squash --delete-branch
```
