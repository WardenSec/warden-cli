# Warden Security Scanner Documentation

## Overview

Warden is a security scanner for Supabase projects. It detects vulnerabilities in live databases, migration files, project settings, and edge functions.

## Vulnerability Reference

| ID | Type | Severity | Description |
|----|------|----------|-------------|
| **RLS-001** | Live | HIGH | Tables without Row Level Security enabled |
| **RLS-002** | Static | MEDIUM | Tables created without `ENABLE ROW LEVEL SECURITY` |
| **POL-002** | Live | HIGH | Policies with `USING (true)` for public/anon roles |
| **POL-003** | Static | MEDIUM | Permissive policies in migration files |
| **FUNC-001** | Live | HIGH | SECURITY DEFINER functions without secure search_path |
| **FUNC-002** | Static | MEDIUM | SECURITY DEFINER functions in migrations without SET search_path |
| **STOR-001** | Live | MEDIUM | Public storage buckets |
| **STOR-002** | Live | HIGH | Permissive policies on storage.objects |
| **PRIV-001** | Live | HIGH | Dangerous grants (TRUNCATE, REFERENCES, ALL) to anon/authenticated |
| **AUTH-001** | API | MEDIUM | Email confirmation disabled |
| **AUTH-002** | API | LOW | Phone confirmation disabled |
| **AUTH-003** | API | LOW | Anonymous users enabled |
| **MFA-001** | API | LOW | MFA not enabled |
| **EDGE-001** | Edge | CRITICAL | Hardcoded secrets in edge functions |
| **EDGE-002** | Edge | HIGH | Missing Authorization header validation |

---

## Scan Types

### 1. Live Database Scan (`--db`)

Connects to your database and checks:
- Tables in `public` schema without RLS
- RLS policies that allow unrestricted access
- SECURITY DEFINER functions with unsafe search paths
- Public storage buckets
- Permissive storage.objects policies
- Dangerous role grants

```bash
warden scan --db "postgres://user:pass@host:5432/db"
```

### 2. Static Migration Scan (`--repo`)

Parses SQL files in migration directories:
- CREATE TABLE without RLS enablement
- CREATE POLICY with overly permissive conditions
- CREATE FUNCTION with SECURITY DEFINER but no search_path

```bash
warden scan --repo . --migrations-path "supabase/migrations"
```

### 3. Management API Scan (`--project-ref`)

Checks Supabase project settings via the Management API:
- Auth confirmation requirements
- Anonymous user settings
- MFA configuration

```bash
warden scan --project-ref "abcdef123456" --access-token "$SUPABASE_ACCESS_TOKEN"
```

### 4. Edge Functions Scan

Scans TypeScript/JavaScript files for:
- Hardcoded API keys, tokens, passwords
- Missing authorization header validation

```bash
warden scan --repo . --functions-path "supabase/functions"
```

---

## Configuration

Warden can be configured using a `warden.yaml` file in the root of your repository.

```yaml
ignore:
  - RLS-002
  - PRIV-001
```

## Suppression

### Global Suppression
Use `warden.yaml` to ignore specific vulnerability checks globally.

### Inline Suppression
You can suppress specific findings in SQL files using comments (applies to the entire file):

```sql
-- warden-disable RLS-002
CREATE TABLE public.public_data ( ... );
```

---

## CLI Reference

```
warden scan [flags]

Flags:
  --db string              Database connection string
  --repo string            Repository URL or local path
  --migrations-path string Path to migrations (default: "supabase/migrations")
  --project-ref string     Supabase project reference
  --access-token string    Supabase access token
  --format string          Output format: json, sarif, text (default: "json")
  --fail-on string         Exit 1 if severity >= threshold (CRITICAL, HIGH, MEDIUM, LOW)
```

---

## Architecture

```
warden/
├── cmd/cli/               # CLI entrypoint
│   ├── main.go
│   └── scan.go            # Scan command
├── internal/
│   ├── domain/            # Core types and interfaces
│   │   └── models.go      # Vulnerability, Policy, Function, Bucket, etc.
│   ├── scanner/           # Business logic
│   │   ├── service.go     # ScanLive, ScanStatic, ScanAPI, ScanEdgeFunctions
│   │   └── service_test.go
│   └── infra/             # External adapters
│       ├── git/           # Git repository operations
│       ├── postgres/      # Database queries
│       ├── parser/        # SQL AST parsing
│       └── supabase/      # Management API client
├── action.yml             # GitHub Action
├── Dockerfile             # Container build
└── test_migrations/       # Test fixtures
```

### Key Interfaces

```go
type DatabaseRepository interface {
    Connect(ctx, connectionString) error
    GetTablesWithoutRLS(ctx) ([]string, error)
    GetPolicies(ctx) ([]Policy, error)
    GetInsecureFunctions(ctx) ([]Function, error)
    GetPublicBuckets(ctx) ([]Bucket, error)
    GetStoragePolicies(ctx) ([]StoragePolicy, error)
    GetRoleGrants(ctx) ([]RoleGrant, error)
}

type GitRepository interface {
    Clone(ctx, url, dest) error
    FindMigrationFiles(dir, subDir) ([]string, error)
    FindEdgeFunctionFiles(dir, subDir) ([]string, error)
}

type ManagementAPI interface {
    GetProjectSettings(ctx, projectRef, accessToken) (*ProjectSettings, error)
}
```

---

## Adding New Checks

1. **Add to domain/models.go**: Define any new structs
2. **Update repository interface**: Add query methods
3. **Implement in infra/**: Add Postgres/Git adapter methods
4. **Add scanner logic**: Implement in `service.go`
5. **Update tests**: Add to `service_test.go`
6. **Update this document**: Add vulnerability ID

---

## Output Formats

### JSON
```json
{
  "vulnerabilities": [
    {
      "id": "RLS-001",
      "title": "Table Without RLS",
      "description": "...",
      "severity": "HIGH",
      "location": "public.users",
      "remediation": "..."
    }
  ]
}
```

### SARIF (GitHub Code Scanning)
Compatible with `github/codeql-action/upload-sarif`.

### Text
Human-readable output with severity icons (🔴 🟠 🟡 🟢).

---

## CI/CD Integration

### GitHub Action

```yaml
- uses: wardensec/warden-action@v1
  with:
    repo: .
    format: sarif
    fail-on: HIGH
```

### Manual

```yaml
- name: Run Warden
  run: |
    go install github.com/wardensec/warden-cli@latest
    warden scan --repo . --format sarif --fail-on HIGH > results.sarif

- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```
