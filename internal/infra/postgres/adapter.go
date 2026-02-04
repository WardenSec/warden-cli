package postgres

import (
	"context"
	"fmt"
	"warden/internal/domain"

	"github.com/jackc/pgx/v5"
)

type PostgresRepository struct {
	conn *pgx.Conn
}

func NewPostgresRepository() *PostgresRepository {
	return &PostgresRepository{}
}

func (r *PostgresRepository) Connect(ctx context.Context, connectionString string) error {
	config, err := pgx.ParseConfig(connectionString)
	if err != nil {
		return fmt.Errorf("unable to parse connection string: %v", err)
	}
	// Force Simple Protocol to support PgBouncer transaction pooling
	config.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol

	conn, err := pgx.ConnectConfig(ctx, config)
	if err != nil {
		return fmt.Errorf("unable to connect to database: %v", err)
	}
	r.conn = conn
	return nil
}

func (r *PostgresRepository) Close(ctx context.Context) error {
	if r.conn != nil {
		return r.conn.Close(ctx)
	}
	return nil
}

func (r *PostgresRepository) GetTablesWithoutRLS(ctx context.Context) ([]string, error) {
	// Query to find tables in public schema that have RLS disabled
	// relrowsecurity is true if RLS is enabled
	query := `
		SELECT n.nspname || '.' || c.relname as table_name
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE c.relkind = 'r' -- only tables
		AND n.nspname = 'public'
		AND c.relrowsecurity = false;
	`
	rows, err := r.conn.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tables []string
	for rows.Next() {
		var tableName string
		if err := rows.Scan(&tableName); err != nil {
			return nil, err
		}
		tables = append(tables, tableName)
	}
	return tables, nil
}

func (r *PostgresRepository) GetPolicies(ctx context.Context) ([]domain.Policy, error) {
	query := `
		SELECT
			p.polname,
			c.relname,
			n.nspname,
			CASE
				WHEN p.polroles = '{0}' THEN ARRAY['public']::text[]
				ELSE p.polroles::regrole[]::text[]
			END,
			p.polcmd,
			COALESCE(pg_get_expr(p.polqual, p.polrelid), ''),
			COALESCE(pg_get_expr(p.polwithcheck, p.polrelid), '')
		FROM pg_policy p
		JOIN pg_class c ON p.polrelid = c.oid
		JOIN pg_namespace n ON c.relnamespace = n.oid
		WHERE n.nspname = 'public'
	`

	rows, err := r.conn.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var policies []domain.Policy
	for rows.Next() {
		var p domain.Policy
		// Scan into temporary variables if needed, but pgx can scan directly into struct fields if order matches?
		// Or scan into variables then construct struct
		if err := rows.Scan(
			&p.Name,
			&p.TableName,
			&p.Schema,
			&p.Roles,
			&p.Cmd,
			&p.Qual,
			&p.WithCheck,
		); err != nil {
			return nil, err
		}
		policies = append(policies, p)
	}
	return policies, nil
}

func (r *PostgresRepository) GetInsecureFunctions(ctx context.Context) ([]domain.Function, error) {
	// Query to find SECURITY DEFINER functions without a secure search_path
	// prosecdef = true means SECURITY DEFINER
	// proconfig contains SET options like search_path
	query := `
		SELECT
			n.nspname AS schema_name,
			p.proname AS function_name,
			p.prosecdef AS is_security_definer,
			COALESCE(
				(SELECT setting FROM unnest(p.proconfig) AS setting WHERE setting LIKE 'search_path=%'),
				''
			) AS search_path_setting
		FROM pg_proc p
		JOIN pg_namespace n ON p.pronamespace = n.oid
		WHERE p.prosecdef = true
		AND n.nspname = 'public';
	`
	rows, err := r.conn.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var functions []domain.Function
	for rows.Next() {
		var f domain.Function
		if err := rows.Scan(&f.Schema, &f.Name, &f.IsSecurityDefiner, &f.SearchPath); err != nil {
			return nil, err
		}
		functions = append(functions, f)
	}
	return functions, nil
}

func (r *PostgresRepository) GetPublicBuckets(ctx context.Context) ([]domain.Bucket, error) {
	// Query Supabase storage.buckets table for public buckets
	query := `
		SELECT id, name, public
		FROM storage.buckets
		WHERE public = true;
	`
	rows, err := r.conn.Query(ctx, query)
	if err != nil {
		// If storage schema doesn't exist, return empty (not an error)
		return nil, nil
	}
	defer rows.Close()

	var buckets []domain.Bucket
	for rows.Next() {
		var b domain.Bucket
		if err := rows.Scan(&b.ID, &b.Name, &b.IsPublic); err != nil {
			return nil, err
		}
		buckets = append(buckets, b)
	}
	return buckets, nil
}

func (r *PostgresRepository) GetStoragePolicies(ctx context.Context) ([]domain.StoragePolicy, error) {
	// Query RLS policies on storage.objects table
	query := `
		SELECT
			p.polname,
			COALESCE(
				(SELECT name FROM storage.buckets WHERE id::text =
					CASE
						WHEN pg_get_expr(p.polqual, p.polrelid) LIKE '%bucket_id%'
						THEN regexp_replace(pg_get_expr(p.polqual, p.polrelid), '.*bucket_id[^'']*''([^'']+)''.*', '\1')
						ELSE ''
					END
				), 'all_buckets'
			) as bucket_name,
			CASE
				WHEN p.polroles = '{0}' THEN ARRAY['public']::text[]
				ELSE p.polroles::regrole[]::text[]
			END as roles,
			p.polcmd,
			COALESCE(pg_get_expr(p.polqual, p.polrelid), ''),
			COALESCE(pg_get_expr(p.polwithcheck, p.polrelid), '')
		FROM pg_policy p
		JOIN pg_class c ON p.polrelid = c.oid
		JOIN pg_namespace n ON c.relnamespace = n.oid
		WHERE n.nspname = 'storage' AND c.relname = 'objects';
	`
	rows, err := r.conn.Query(ctx, query)
	if err != nil {
		// If storage schema doesn't exist, return empty
		return nil, nil
	}
	defer rows.Close()

	var policies []domain.StoragePolicy
	for rows.Next() {
		var p domain.StoragePolicy
		if err := rows.Scan(&p.Name, &p.BucketID, &p.Roles, &p.Cmd, &p.Qual, &p.WithCheck); err != nil {
			return nil, err
		}
		policies = append(policies, p)
	}
	return policies, nil
}

func (r *PostgresRepository) GetRoleGrants(ctx context.Context) ([]domain.RoleGrant, error) {
	// Query for dangerous privileges granted to anon/authenticated roles
	query := `
		SELECT
			grantee,
			table_schema,
			table_name,
			array_agg(privilege_type) as privileges
		FROM information_schema.role_table_grants
		WHERE grantee IN ('anon', 'authenticated', 'public')
		AND table_schema = 'public'
		GROUP BY grantee, table_schema, table_name;
	`
	rows, err := r.conn.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var grants []domain.RoleGrant
	for rows.Next() {
		var g domain.RoleGrant
		if err := rows.Scan(&g.Role, &g.Schema, &g.TableName, &g.Privileges); err != nil {
			return nil, err
		}
		grants = append(grants, g)
	}
	return grants, nil
}
