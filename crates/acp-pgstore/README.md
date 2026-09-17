# acp-pgstore

Postgres tenant-isolated store (v1.1.1 / H1.1). Isolation is enforced by Postgres Row-Level
Security with FORCE, so one tenant can never read or write another's rows, even via a bare
unfiltered `SELECT`. The tenant is set per transaction and is never trusted from row payload.

## Why a dedicated role matters

RLS (even FORCE) is bypassed for superusers and BYPASSRLS roles. The application must therefore
connect as an ordinary role. Set up once:

```sql
CREATE ROLE acp_app LOGIN PASSWORD 'acp' NOSUPERUSER NOBYPASSRLS;
GRANT CONNECT ON DATABASE acp_test TO acp_app;
GRANT CREATE, USAGE ON SCHEMA public TO acp_app;
-- acp_app then creates and owns the `records` table via init_schema(), so FORCE RLS applies to it.
```

## Running the isolation test

The test is gated on `ACP_PG_TEST_URL` so a machine without Postgres skips it:

```sh
ACP_PG_TEST_URL="postgresql://acp_app:acp@localhost:5432/acp_test" cargo test -p acp-pgstore
```

Production points the same code at a managed Postgres by changing the URL only.
