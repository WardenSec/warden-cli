package domain

import (
	"context"
)

// Vulnerability represents a security issue found during scanning.
type Vulnerability struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Severity    string `json:"severity"` // "LOW", "MEDIUM", "HIGH", "CRITICAL"
	Location    string `json:"location"` // File path or DB object name
	Remediation string `json:"remediation"`
}

// WardenConfig represents the global configuration from warden.yaml.
type WardenConfig struct {
	Ignore []string `yaml:"ignore" json:"ignore"`
}

// ScanResult aggregates vulnerabilities found.
type ScanResult struct {
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

// Append merges another ScanResult into this one.
func (s *ScanResult) Append(other *ScanResult) {
	if other != nil {
		s.Vulnerabilities = append(s.Vulnerabilities, other.Vulnerabilities...)
	}
}

// Policy represents a Row Level Security policy.
type Policy struct {
	Name      string
	TableName string
	Schema    string
	Roles     []string
	Cmd       string // SELECT, INSERT, UPDATE, DELETE, ALL
	Qual      string // USING expression
	WithCheck string // WITH CHECK expression
}

// Function represents a PostgreSQL function for security analysis.
type Function struct {
	Schema            string
	Name              string
	IsSecurityDefiner bool
	SearchPath        string // empty if not set
}

// Bucket represents a Supabase Storage bucket.
type Bucket struct {
	ID       string
	Name     string
	IsPublic bool
}

// StoragePolicy represents an RLS policy on storage.objects.
type StoragePolicy struct {
	Name      string
	BucketID  string
	Roles     []string
	Cmd       string // SELECT, INSERT, UPDATE, DELETE
	Qual      string // USING expression
	WithCheck string // WITH CHECK expression
}

// RoleGrant represents a privilege grant to a database role.
type RoleGrant struct {
	Role       string
	Schema     string
	TableName  string
	Privileges []string // SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, ALL
}

// DatabaseRepository defines the interface for interacting with the live database.
type DatabaseRepository interface {
	Connect(ctx context.Context, connectionString string) error
	Close(ctx context.Context) error
	GetTablesWithoutRLS(ctx context.Context) ([]string, error)
	GetPolicies(ctx context.Context) ([]Policy, error)
	GetInsecureFunctions(ctx context.Context) ([]Function, error)
	GetPublicBuckets(ctx context.Context) ([]Bucket, error)
	GetStoragePolicies(ctx context.Context) ([]StoragePolicy, error)
	GetRoleGrants(ctx context.Context) ([]RoleGrant, error)
}

// GitRepository defines the interface for interacting with git repositories.
type GitRepository interface {
	Clone(ctx context.Context, url string, dest string) error
	FindMigrationFiles(dir string, subDir string) ([]string, error)
	FindEdgeFunctionFiles(dir string, subDir string) ([]string, error)
}

// SQLParser defines the interface for parsing SQL files.
type SQLParser interface {
	Parse(sql string) (interface{}, error) // Returns AST or error
}

// ProjectSettings represents relevant security settings from the Management API.
type ProjectSettings struct {
	EmailConfirmRequired  bool
	PhoneConfirmRequired  bool
	AnonymousUsersEnabled bool
	MFAEnabled            bool
}

// ManagementAPI defines the interface for interacting with the Supabase Management API.
type ManagementAPI interface {
	GetProjectSettings(ctx context.Context, projectRef, accessToken string) (*ProjectSettings, error)
}
