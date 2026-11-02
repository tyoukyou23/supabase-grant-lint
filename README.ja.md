# supabase-grant-lint

**Supabase の migration にある RLS・GRANT・REVOKE の書き漏れを、出荷する前に見つける。**

[Playground](https://tyoukyou23.github.io/supabase-grant-lint/) · [English](./README.md)

```sh
npx supabase-grant-lint
```

```
error  todos  client-table-no-grant
       supabase/migrations/20261102000000_todos.sql:1
       The browser client queries this table, but neither anon nor authenticated is granted anything on it (42501 permission denied).
       fix: GRANT SELECT ON todos TO authenticated;  -- only the operations your RLS policies allow
```

`supabase/migrations/*.sql` を順に読み、`CREATE TABLE` / `VIEW` / `FUNCTION`・`GRANT`・`REVOKE`・`ALTER DEFAULT PRIVILEGES`・`ALTER ... RENAME / SET SCHEMA`・`DROP` を再生して、**最終的にどの役割がどの権限を持っているか**を求めます。DB への接続も Docker も不要です。CI でプルリクエストごとに 1 秒ほどで回ります（メッセージは英語です）。

## なぜ要るのか

ここで扱う間違いは、どれも `supabase db push` もテストも通り、画面も正しく動きます。その表を読む画面を誰かが開くまで、あるいは誰かが anon key で関数を呼ぶまで気付けません。

- **Supabase は新しい表を自動公開しなくなる。** 2026-05-30 以降の新規プロジェクトと、既存プロジェクトで **2026-10-30** 以降に作る表には、`anon`・`authenticated`・`service_role` の `SELECT/INSERT/UPDATE/DELETE` が付きません（sequence の `USAGE/SELECT` も同様）。ローカルの `supabase db reset` も `auto_expose_new_tables = false` なら同じです。明示 `GRANT` の無い表は、RLS policy が正しくても `42501 permission denied` になります。（[changelog](https://supabase.com/changelog/45329-breaking-change-tables-not-exposed-to-data-and-graphql-api-automatically)）
- **`GRANT` は加算、`REVOKE ALL` は全消し。** `GRANT SELECT ... TO authenticated;` の後に `REVOKE ALL ... FROM anon, authenticated;` と書くと、authenticated には何も残りません。
- **関数は今も既定で誰でも実行できる。** PostgreSQL は `EXECUTE` を `PUBLIC` に付け、Supabase はさらに `anon`・`authenticated` にも付けます。`SECURITY DEFINER` 関数は RLS を素通りするので、利用者 id を引数で受け取る関数なら、誰でも `/rpc/関数名` から他人として操作できます。`REVOKE ... FROM PUBLIC` だけでは `anon` 自身への付与は消えません。
- **`REVOKE` が指すのは 1 つの多重定義だけ。** 引数を足して `CREATE OR REPLACE` すると関数は 2 つになり、前の `REVOKE` は古い方しか守りません。
- **ビューは既定で RLS を無視する。** `WITH (security_invoker = on)` で作らない限り、ビューは所有者の権限で動きます。RLS で守った表の上のビューは、`anon` に全行を見せうるということです。

Supabase の [Security Advisor](https://supabase.com/docs/guides/database/database-advisors) は稼働中の DB で一部を事後に見つけます。このツールは、それを持ち込むプルリクエストの migration の段階で止めます。

## 規則

| 規則 | recommended | strict | 何を見つけるか |
|---|---|---|---|
| `rls-disabled` | error | error | 公開スキーマの表に `ENABLE ROW LEVEL SECURITY` が無い（`FORCE` だけでは有効にならない） |
| `view-bypasses-rls` | error | error | `security_invoker` の無いビュー、またはマテリアライズドビューを `anon`/`authenticated` が `SELECT` できる |
| `grant-order` | error | error | 同じ migration で、同じ役割への `GRANT` の後に `REVOKE ALL` があり、付け直されない権限が消える |
| `client-table-no-grant` | error | error | ブラウザのコードが `.from("表")` で読むのに、`anon` にも `authenticated` にも権限が無い（`client` 設定が必要） |
| `definer-public-execute` | error | error | `SECURITY DEFINER` 関数を `PUBLIC` / `anon` がまだ実行できる。`REVOKE` が別の多重定義を指している場合も含む |
| `missing-service-role-grant` | warn | error | 新しい表が自動公開されない環境で、`service_role` に表の権限が無い |
| `serial-sequence-grant` | warn | error | INSERT できる役割が `serial` 列の sequence に `USAGE` を持っていない |
| `missing-explicit-revoke` | off | error | `REVOKE ... FROM anon, authenticated` が明示されていない |
| `anon-table-access` | off | error | `anon`（または `PUBLIC`）が SELECT/INSERT/UPDATE/DELETE を持っている。RLS は効くので多層防御の観点 |
| `rls-per-row-call` | warn | error | policy が `auth.uid()` / `auth.role()` / `auth.jwt()` や migration で作った引数なしの判定関数を `(select ...)` で包まずに呼んでいて、行ごとに評価される。表を引く関数だと、全表走査のたびに行数ぶんの問い合わせになる |

`strict` はすべての表の権限を明示したいチーム向けです。既存プロジェクトでは [baseline](#既存プロジェクトへの導入-baseline) と組み合わせて導入してください。

検査するのは Data API に公開しているスキーマだけです。trigger 関数とプロシージャは PostgREST から呼べないので対象外です。`GRANT EXECUTE ... TO anon` を関数ごとに明示したものは意図どおりとみなします。

`strict` を通る形:

```sql
CREATE TABLE notes (id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, owner uuid NOT NULL, body text);
ALTER TABLE notes ENABLE ROW LEVEL SECURITY;
CREATE POLICY "owner" ON notes FOR ALL TO authenticated USING (owner = (select auth.uid()));

REVOKE ALL ON notes FROM anon, authenticated;                       -- REVOKE を先に
GRANT SELECT, INSERT, UPDATE, DELETE ON notes TO authenticated;     -- policy が許す操作だけ
GRANT SELECT, INSERT, UPDATE, DELETE ON notes TO service_role;

CREATE VIEW my_notes WITH (security_invoker = on) AS SELECT * FROM notes;
GRANT SELECT ON my_notes TO authenticated;

CREATE FUNCTION is_team_admin(p_team uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$ ... $$;
REVOKE ALL ON FUNCTION is_team_admin(uuid) FROM PUBLIC, anon;       -- 引数の型を正確に
GRANT EXECUTE ON FUNCTION is_team_admin(uuid) TO authenticated;     -- RLS policy から呼ぶ場合
```

## 2 つの世界

Supabase の migration は、新しい表が自動公開される環境（古いプロジェクト、2026-10-30 より前に作った表）と、されない環境（新規プロジェクト、`db reset`、それ以降に作る表）の両方で正しくなければなりません。既定（`"defaults": "both"`）では migration を両方の世界で再生し、規則ごとに**それが破れうる方の世界**で判定します。

- **開きすぎ**（`anon-table-access`・`view-bypasses-rls`・`definer-public-execute`）: 全部に付与される世界で見ます。本番の表には実際にその権限が残っているからです。
- **付け忘れ**（`client-table-no-grant`・`missing-service-role-grant`・`serial-sequence-grant`）: 何も付与されない世界で見ます。新しい環境はそうなるからです。

全環境がどちらか一方なら `"defaults": "auto-expose"` か `"no-auto-expose"` を指定します。どちらの場合も migration 中の `ALTER DEFAULT PRIVILEGES` を順に上乗せします。`FOR ROLE` は考慮し、migration を流す役割（`migrationRole`、既定 `postgres`）の分だけを数えます。

## 設定

任意です。プロジェクト直下に `supabase-grant-lint.config.json`（または `package.json` の `"supabaseGrantLint"`）を置きます。知らないキーや不正な値はエラーにするので、書き間違いで検査が黙って弱まることはありません。

```json
{
  "migrations": "supabase/migrations",
  "preset": "recommended",
  "schemas": ["public"],
  "defaults": "both",
  "migrationRole": "postgres",
  "rules": { "serial-sequence-grant": "error" },
  "client": {
    "marker": "lib/supabaseClient",
    "include": ["src", "app", "pages", "components", "hooks", "lib"],
    "exclude": ["pages/api", "app/api", "supabase"]
  }
}
```

- **`schemas`** の既定は `supabase/config.toml` の `[api] schemas` です。それが無ければ `["public"]` を使います。
- **`client`** を書くと `client-table-no-grant` が有効になります。`include` 配下で `marker`（正規表現。ふつうは**ブラウザ用** Supabase クライアントの import）に一致するファイルから `.from("表")` を拾います。`supabase.storage.from("bucket")` や `Array.from(...)` は無視します。サーバ専用のコードは `exclude` で外します。

## 既存プロジェクトへの導入: baseline

古いプロジェクトには、今すぐは直せない指摘があります。一度記録すれば、以後は**新しく増えたもの**だけが落ちます。

```sh
npx supabase-grant-lint --write-baseline     # supabase-grant-lint.baseline.json を書く（コミットする）
npx supabase-grant-lint                      # 通る。RLS の無い新しい表はやはり落ちる
npx supabase-grant-lint --prune-baseline     # 直した分を baseline から消す
```

項目は `schema.object::rule`（例: `public.posts::rls-disabled`）なので、`supabase migration squash` やファイル名の変更をしても有効です。baseline は減る一方です。既存の baseline に新しい項目を足す `--write-baseline` は `--force` が無いと拒否し、`--fail-on-stale` を付けると直った項目の消し忘れも CI で落とせます。

## コメント指示

```sql
-- grant-lint-ignore anon-table-access
CREATE TABLE public_announcements (...);   -- 意図してログイン無しで読ませる表
```

`-- grant-lint-ignore [規則, ...]` は次の 1 文に効きます（規則を書かなければ全部）。対象の `CREATE` の上か、指摘が指している文の上に書きます（`grant-order` なら `REVOKE` の上）。

```sql
-- grant-lint-as: REVOKE ALL ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC, anon;
DO $$
DECLARE r record;
BEGIN
  FOR r IN SELECT p.oid::regprocedure AS sig FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
           WHERE n.nspname = 'public'
  LOOP
    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC, anon', r.sig);
  END LOOP;
END $$;
```

`DO` ブロック内の動的 SQL は静的には読めません。`-- grant-lint-as: <SQL>` で「このブロックはこの SQL と同じ」と書くと、その SQL をその位置で解析します。

## CI

```yaml
# .github/workflows/migrations.yml
name: migrations
on: [pull_request]
jobs:
  grants:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 22 }
      - run: npx supabase-grant-lint --format github
```

`--format github` はプルリクエストの差分に注釈として出します。`--format json` は他の道具向けに全部を出します。

## CLI

```
--dir <path>          migration のディレクトリ（既定: supabase/migrations）
--config <path>       設定ファイル
--preset <name>       recommended | strict
--format <name>       text | json | github
--no-baseline         baseline を無視する
--write-baseline      今の指摘をすべて baseline に記録する
--force               --write-baseline で既存の baseline に項目を足すことを許す
--prune-baseline      直った項目を baseline から消す
--fail-on-stale       直った項目が baseline に残っていたら終了コード 1
--list-rules          規則と preset ごとの重さを表示する
```

終了コード: `0` 新しいエラー無し（warning では落ちない）、`1` 新しいエラーあり、`2` 使い方・設定の誤り（migration のディレクトリが空の場合を含む）。Node.js 20 以上が必要です。

## API

```ts
import { analyze } from "supabase-grant-lint";           // 純粋関数。ブラウザでも動く
import { lintProject } from "supabase-grant-lint/node";   // ファイル・設定・baseline を読む

const { violations } = analyze(
  [{ name: "001_init.sql", sql: "CREATE TABLE posts (id int);" }],
  { preset: "strict", clientTables: ["posts"] }
);
```

## どう検証しているか

単体テストに加えて、実物の PostgreSQL と突き合わせています。乱数で生成した migration を、Supabase の既定権限を再現した PostgreSQL と、自動公開を切った PostgreSQL の両方で実行します。そこで最終的に付いた権限（`has_table_privilege`・`has_function_privilege`・`relrowsecurity`・ビューの設定）を、リンターが導いた結果と比べています。公開されている Supabase プロジェクトの migration でも実際に走らせています。

## 限界

- migration の検査であって DB の走査ではありません。ダッシュボードから手で変えた権限は見えません。Supabase の Security Advisor も併用してください。
- 動的 SQL（`EXECUTE format(...)`）は実行しません。`grant-lint-as` を使ってください。
- まだ見ていないもの: RLS policy が何を許しているか（関数の呼び方だけを見ています）、スキーマ名を書かずに `SET search_path` で作った物、`SELECT ... INTO`、`supabase/schemas/` の宣言的スキーマ。
- 列単位の付与（`GRANT SELECT (列)`）は表への権限として数えます。

## ライセンス

MIT
