package scanner

import (
	"context"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"strings"
	"warden/internal/domain"

	pg_query "github.com/pganalyze/pg_query_go/v5"
)

type Scanner struct {
	dbRepo  domain.DatabaseRepository
	gitRepo domain.GitRepository
	apiRepo domain.ManagementAPI
	parser  domain.SQLParser
	config  domain.WardenConfig
}

func NewScanner(db domain.DatabaseRepository, git domain.GitRepository, api domain.ManagementAPI, parser domain.SQLParser, config domain.WardenConfig) *Scanner {
	return &Scanner{
		dbRepo:  db,
		gitRepo: git,
		apiRepo: api,
		parser:  parser,
		config:  config,
	}
}

func (s *Scanner) isIgnored(id string) bool {
	for _, deferredID := range s.config.Ignore {
		if deferredID == id {
			return true
		}
	}
	return false
}

func (s *Scanner) reportVulnerability(result *domain.ScanResult, id, title, desc, severity, location, remediation string) {
	if s.isIgnored(id) {
		return
	}

	result.Vulnerabilities = append(result.Vulnerabilities, domain.Vulnerability{
		ID:          id,
		Title:       title,
		Description: desc,
		Severity:    severity,
		Location:    location,
		Remediation: remediation,
	})
}

func (s *Scanner) ScanLive(ctx context.Context, connectionString string) (*domain.ScanResult, error) {
	result := &domain.ScanResult{}

	if err := s.dbRepo.Connect(ctx, connectionString); err != nil {
		return nil, err
	}
	defer s.dbRepo.Close(ctx)

	if err := s.scanLiveTables(ctx, result); err != nil {
		return nil, err
	}

	if err := s.scanLivePolicies(ctx, result); err != nil {
		return nil, err
	}

	if err := s.scanLiveFunctions(ctx, result); err != nil {
		return nil, err
	}

	if err := s.scanLiveBuckets(ctx, result); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Could not check storage buckets: %v\n", err)
	}

	if err := s.scanLiveStoragePolicies(ctx, result); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Could not check storage policies: %v\n", err)
	}

	if err := s.scanLiveGrants(ctx, result); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Could not check role grants: %v\n", err)
	}

	return result, nil
}

func (s *Scanner) scanLiveTables(ctx context.Context, result *domain.ScanResult) error {
	tables, err := s.dbRepo.GetTablesWithoutRLS(ctx)
	if err != nil {
		return err
	}
	for _, table := range tables {
		s.reportVulnerability(result, "RLS-001", "Row Level Security Disabled",
			fmt.Sprintf("Table %s has RLS disabled. This allows unrestricted access if policies are not enforced.", table),
			"CRITICAL", table,
			fmt.Sprintf("Enable RLS on table %s: ALTER TABLE %s ENABLE ROW LEVEL SECURITY;", table, table))
	}
	return nil
}

func (s *Scanner) scanLivePolicies(ctx context.Context, result *domain.ScanResult) error {
	policies, err := s.dbRepo.GetPolicies(ctx)
	if err != nil {
		return err
	}
	for _, p := range policies {
		isPublic := false
		for _, r := range p.Roles {
			if r == "public" || r == "anon" {
				isPublic = true
				break
			}
		}

		if isPublic && p.Qual == "true" {
			s.reportVulnerability(result, "POL-002", "Permissive Policy Detected (Live)",
				fmt.Sprintf("Policy '%s' on table '%s.%s' allows access with USING (true) to public/anon roles.", p.Name, p.Schema, p.TableName),
				"HIGH", fmt.Sprintf("%s.%s (%s)", p.Schema, p.TableName, p.Name),
				"Review the policy. Ensure it restricts access to authorized users only.")
		}
	}
	return nil
}

func (s *Scanner) scanLiveFunctions(ctx context.Context, result *domain.ScanResult) error {
	functions, err := s.dbRepo.GetInsecureFunctions(ctx)
	if err != nil {
		return err
	}
	for _, f := range functions {
		if f.SearchPath == "" || f.SearchPath != "search_path=" {
			s.reportVulnerability(result, "FUNC-001", "Insecure SECURITY DEFINER Function",
				fmt.Sprintf("Function '%s.%s' uses SECURITY DEFINER without a secure search_path. This can lead to privilege escalation.", f.Schema, f.Name),
				"HIGH", fmt.Sprintf("%s.%s", f.Schema, f.Name),
				"Add 'SET search_path = \"\"' to the function definition to prevent search_path hijacking.")
		}
	}
	return nil
}

func (s *Scanner) scanLiveBuckets(ctx context.Context, result *domain.ScanResult) error {
	buckets, err := s.dbRepo.GetPublicBuckets(ctx)
	if err != nil {
		return err
	}
	for _, b := range buckets {
		s.reportVulnerability(result, "STOR-001", "Public Storage Bucket",
			fmt.Sprintf("Bucket '%s' is configured as public. Anyone can read objects from this bucket.", b.Name),
			"MEDIUM", fmt.Sprintf("storage.buckets.%s", b.Name),
			"Review if this bucket needs to be public. If not, set 'public' to false and use RLS policies for access control.")
	}
	return nil
}

func (s *Scanner) scanLiveStoragePolicies(ctx context.Context, result *domain.ScanResult) error {
	storagePolicies, err := s.dbRepo.GetStoragePolicies(ctx)
	if err != nil {
		return err
	}
	for _, p := range storagePolicies {
		isPublic := false
		for _, r := range p.Roles {
			if r == "public" || r == "anon" {
				isPublic = true
				break
			}
		}

		if isPublic && p.Qual == "true" {
			s.reportVulnerability(result, "STOR-002", "Permissive Storage Policy",
				fmt.Sprintf("Policy '%s' on storage.objects allows unrestricted access to bucket '%s' with USING (true).", p.Name, p.BucketID),
				"HIGH", fmt.Sprintf("storage.objects (%s)", p.Name),
				"Restrict the policy to specific users or conditions instead of USING (true).")
		}
	}
	return nil
}

func (s *Scanner) scanLiveGrants(ctx context.Context, result *domain.ScanResult) error {
	roleGrants, err := s.dbRepo.GetRoleGrants(ctx)
	if err != nil {
		return err
	}
	dangerousPrivileges := map[string]bool{"TRUNCATE": true, "REFERENCES": true, "ALL": true}
	for _, g := range roleGrants {
		for _, priv := range g.Privileges {
			if dangerousPrivileges[priv] {
				s.reportVulnerability(result, "PRIV-001", "Dangerous Role Grant",
					fmt.Sprintf("Role '%s' has %s privilege on table '%s.%s'. This could allow data destruction or privilege escalation.", g.Role, priv, g.Schema, g.TableName),
					"HIGH", fmt.Sprintf("%s.%s (role: %s)", g.Schema, g.TableName, g.Role),
					fmt.Sprintf("Review if %s privilege is necessary for role '%s'. Consider revoking dangerous privileges.", priv, g.Role))
				break // Only report once per table/role combination
			}
		}
	}
	return nil
}

type staticScanContext struct {
	tablesCreated       map[string]string // tableName -> file
	tablesWithRLS       map[string]bool   // tableName -> hasRLS
	tablesSuppressedRLS map[string]bool   // tableName -> isSuppressed
	suppressedIDs       map[string]bool   // current file suppressed IDs
	currentFile         string
}

func newStaticScanContext() *staticScanContext {
	return &staticScanContext{
		tablesCreated:       make(map[string]string),
		tablesWithRLS:       make(map[string]bool),
		tablesSuppressedRLS: make(map[string]bool),
		suppressedIDs:       make(map[string]bool),
	}
}

func (s *Scanner) ScanStatic(ctx context.Context, repoURL string, migrationsPath string) (*domain.ScanResult, error) {
	result := &domain.ScanResult{}

	// Create temp dir
	tmpDir, err := ioutil.TempDir("", "warden-scan")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir)

	if err := s.gitRepo.Clone(ctx, repoURL, tmpDir); err != nil {
		return nil, err
	}

	// Use provided migrationsPath (e.g. "supabase/migrations")
	files, err := s.gitRepo.FindMigrationFiles(tmpDir, migrationsPath)
	if err != nil {
		return nil, err
	}

	scanCtx := newStaticScanContext()

	for _, file := range files {
		scanCtx.currentFile = file
		if err := s.processMigrationFile(file, scanCtx, result); err != nil {
			continue
		}
	}

	// After processing all files, check for tables without RLS
	s.checkMissingRLS(scanCtx, result)

	// LEAK-001: Check for service role key leaks in .env files
	s.checkEnvSecrets(tmpDir, result)

	return result, nil
}

func (s *Scanner) processMigrationFile(file string, scanCtx *staticScanContext, result *domain.ScanResult) error {
	content, err := ioutil.ReadFile(file)
	if err != nil {
		return err
	}
	contentStr := string(content)

	// Parse suppression comments
	scanCtx.suppressedIDs = make(map[string]bool)
	suppressPattern := regexp.MustCompile(`--\s*warden-disable\s+(\S+)`)
	for _, match := range suppressPattern.FindAllStringSubmatch(contentStr, -1) {
		if len(match) > 1 {
			scanCtx.suppressedIDs[match[1]] = true
		}
	}

	ast, err := s.parser.Parse(contentStr)
	if err != nil {
		return err
	}

	parseResult, ok := ast.(*pg_query.ParseResult)
	if !ok {
		return nil
	}

	for _, stmt := range parseResult.Stmts {
		s.analyzeStatement(stmt, scanCtx, result)
	}
	return nil
}

func (s *Scanner) analyzeStatement(stmt *pg_query.RawStmt, scanCtx *staticScanContext, result *domain.ScanResult) {
	if createStmt := stmt.Stmt.GetCreateStmt(); createStmt != nil {
		s.analyzeCreateTable(createStmt, scanCtx, result)
	}
	if alterStmt := stmt.Stmt.GetAlterTableStmt(); alterStmt != nil {
		s.analyzeAlterTable(alterStmt, scanCtx)
	}
	if createFunc := stmt.Stmt.GetCreateFunctionStmt(); createFunc != nil {
		s.analyzeCreateFunction(createFunc, scanCtx, result)
	}
	if grantStmt := stmt.Stmt.GetGrantStmt(); grantStmt != nil && grantStmt.IsGrant {
		s.analyzeGrant(grantStmt, scanCtx, result)
	}
	if createPolicy := stmt.Stmt.GetCreatePolicyStmt(); createPolicy != nil {
		s.analyzeCreatePolicy(createPolicy, scanCtx, result)
	}
}

func (s *Scanner) analyzeCreateTable(stmt *pg_query.CreateStmt, scanCtx *staticScanContext, result *domain.ScanResult) {
	schemaName := "public"
	if stmt.Relation.Schemaname != "" {
		schemaName = stmt.Relation.Schemaname
	}
	tableName := stmt.Relation.Relname
	fullName := fmt.Sprintf("%s.%s", schemaName, tableName)
	scanCtx.tablesCreated[fullName] = scanCtx.currentFile

	if scanCtx.suppressedIDs["RLS-002"] {
		scanCtx.tablesSuppressedRLS[fullName] = true
	}

	// INFO-001: Check for SERIAL/BIGSERIAL columns
	for _, elt := range stmt.TableElts {
		if colDef := elt.GetColumnDef(); colDef != nil && colDef.TypeName != nil {
			for _, name := range colDef.TypeName.Names {
				if str := name.GetString_(); str != nil {
					typeName := strings.ToLower(str.Sval)
					if typeName == "serial" || typeName == "bigserial" || typeName == "serial4" || typeName == "serial8" {
						if !scanCtx.suppressedIDs["INFO-001"] {
							s.reportVulnerability(result, "INFO-001", "Incremental ID Detected",
								fmt.Sprintf("Column '%s' in table '%s' uses %s. Incremental IDs can leak business metrics and enable data scraping.", colDef.Colname, fullName, strings.ToUpper(typeName)),
								"LOW", fmt.Sprintf("%s.%s in %s", fullName, colDef.Colname, scanCtx.currentFile),
								"Consider using UUID primary keys instead: 'id uuid PRIMARY KEY DEFAULT gen_random_uuid()'.")
						}
					}
				}
			}
		}
	}
}

func (s *Scanner) analyzeAlterTable(stmt *pg_query.AlterTableStmt, scanCtx *staticScanContext) {
	schemaName := "public"
	if stmt.Relation.Schemaname != "" {
		schemaName = stmt.Relation.Schemaname
	}
	tableName := stmt.Relation.Relname
	fullName := fmt.Sprintf("%s.%s", schemaName, tableName)

	for _, cmd := range stmt.Cmds {
		if alterCmd := cmd.GetAlterTableCmd(); alterCmd != nil {
			if alterCmd.Subtype == pg_query.AlterTableType_AT_EnableRowSecurity {
				scanCtx.tablesWithRLS[fullName] = true
			}
		}
	}
}

func (s *Scanner) analyzeCreateFunction(stmt *pg_query.CreateFunctionStmt, scanCtx *staticScanContext, result *domain.ScanResult) {
	isSecurityDefiner := false
	hasSecureSearchPath := false

	for _, option := range stmt.Options {
		if defElem := option.GetDefElem(); defElem != nil {
			if defElem.Defname == "security" {
				if boolVal := defElem.Arg.GetBoolean(); boolVal != nil {
					isSecurityDefiner = boolVal.Boolval
				}
			}
			if defElem.Defname == "set" {
				hasSecureSearchPath = true
			}
		}
	}

	if isSecurityDefiner && !hasSecureSearchPath {
		funcName := ""
		for _, part := range stmt.Funcname {
			if str := part.GetString_(); str != nil {
				funcName = str.Sval
			}
		}
		if !scanCtx.suppressedIDs["FUNC-002"] {
			s.reportVulnerability(result, "FUNC-002", "Insecure SECURITY DEFINER Function (Static)",
				fmt.Sprintf("Function '%s' uses SECURITY DEFINER without SET search_path.", funcName),
				"HIGH", fmt.Sprintf("%s in %s", funcName, scanCtx.currentFile),
				"Add 'SET search_path = \"\"' to the function definition.")
		}
	}
}

func (s *Scanner) analyzeGrant(stmt *pg_query.GrantStmt, scanCtx *staticScanContext, result *domain.ScanResult) {
	for _, grantee := range stmt.Grantees {
		if rs := grantee.GetRoleSpec(); rs != nil {
			roleName := rs.GetRolename()
			if roleName == "anon" || roleName == "authenticated" {
				if len(stmt.Privileges) == 0 {
					if !scanCtx.suppressedIDs["PRIV-001"] {
						s.reportVulnerability(result, "PRIV-001", "Dangerous Grant (Static)",
							fmt.Sprintf("GRANT ALL to '%s' detected. This could allow data destruction or privilege escalation.", roleName),
							"HIGH", scanCtx.currentFile,
							fmt.Sprintf("Review if ALL privilege is necessary for role '%s'. Grant only specific required privileges.", roleName))
					}
				} else {
					for _, priv := range stmt.Privileges {
						if accessPriv := priv.GetAccessPriv(); accessPriv != nil {
							privName := strings.ToUpper(accessPriv.PrivName)
							if privName == "TRUNCATE" || privName == "REFERENCES" {
								if !scanCtx.suppressedIDs["PRIV-001"] {
									s.reportVulnerability(result, "PRIV-001", "Dangerous Grant (Static)",
										fmt.Sprintf("GRANT %s to '%s' detected. This could allow data destruction or privilege escalation.", privName, roleName),
										"HIGH", scanCtx.currentFile,
										fmt.Sprintf("Review if %s privilege is necessary for role '%s'.", privName, roleName))
								}
							}
						}
					}
				}
			}
		}
	}
}

func (s *Scanner) analyzeCreatePolicy(stmt *pg_query.CreatePolicyStmt, scanCtx *staticScanContext, result *domain.ScanResult) {
	isPublic := false
	if len(stmt.Roles) == 0 {
		isPublic = true
	} else {
		for _, role := range stmt.Roles {
			if rs := role.GetRoleSpec(); rs != nil {
				if rs.Roletype == pg_query.RoleSpecType_ROLESPEC_PUBLIC {
					isPublic = true
					break
				}
				roleName := rs.GetRolename()
				if roleName == "public" || roleName == "anon" {
					isPublic = true
					break
				}
			}
		}
	}

	if isPublic {
		isPermissive := false
		if stmt.Qual != nil {
			if aConst := stmt.Qual.GetAConst(); aConst != nil {
				if boolVal, ok := aConst.Val.(*pg_query.A_Const_Boolval); ok {
					if boolVal.Boolval.Boolval {
						isPermissive = true
					}
				}
			}
		}

		if isPermissive {
			if !scanCtx.suppressedIDs["POL-003"] {
				s.reportVulnerability(result, "POL-003", "Permissive Policy Detected (Static)",
					fmt.Sprintf("Policy '%s' allows access with USING (true) to public/anon roles.", stmt.PolicyName),
					"HIGH", fmt.Sprintf("%s in %s", stmt.PolicyName, scanCtx.currentFile),
					"Review the policy definition. Ensure it restricts access to authorized users only.")
			}
		}
	}
}

func (s *Scanner) checkMissingRLS(scanCtx *staticScanContext, result *domain.ScanResult) {
	for tableName, createdInFile := range scanCtx.tablesCreated {
		if !scanCtx.tablesWithRLS[tableName] && !scanCtx.tablesSuppressedRLS[tableName] {
			s.reportVulnerability(result, "RLS-002", "Missing RLS (Static)",
				fmt.Sprintf("Table '%s' was created but RLS was never enabled in migrations.", tableName),
				"CRITICAL", fmt.Sprintf("%s (created in %s)", tableName, createdInFile),
				fmt.Sprintf("Add 'ALTER TABLE %s ENABLE ROW LEVEL SECURITY;' to your migrations.", tableName))
		}
	}
}

func (s *Scanner) checkEnvSecrets(tmpDir string, result *domain.ScanResult) {
	envPatterns := []string{".env", ".env.local", ".env.development", ".env.production", ".env.staging"}
	secretPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)SUPABASE_SERVICE_ROLE_KEY\s*=\s*[^\s]+`),
		regexp.MustCompile(`(?i)SERVICE_ROLE_KEY\s*=\s*[^\s]+`),
		regexp.MustCompile(`(?i)SUPABASE_SECRET\s*=\s*[^\s]+`),
	}

	for _, envFile := range envPatterns {
		envPath := fmt.Sprintf("%s/%s", tmpDir, envFile)
		if content, err := ioutil.ReadFile(envPath); err == nil {
			contentStr := string(content)
			for _, pattern := range secretPatterns {
				if matches := pattern.FindAllString(contentStr, -1); len(matches) > 0 {
					s.reportVulnerability(result, "LEAK-001", "Service Role Key Leaked",
						fmt.Sprintf("Found potential service role key in '%s'. This key should NEVER be committed to source control.", envFile),
						"CRITICAL", envFile,
						"Remove the service role key from version control. Use environment variables or secret management. Add the file to .gitignore.")
					break // Only report once per file
				}
			}
		}
	}
}

// ScanAPI checks project settings via the Supabase Management API.
func (s *Scanner) ScanAPI(ctx context.Context, projectRef, accessToken string) (*domain.ScanResult, error) {
	result := &domain.ScanResult{}

	settings, err := s.apiRepo.GetProjectSettings(ctx, projectRef, accessToken)
	if err != nil {
		return nil, fmt.Errorf("failed to get project settings: %w", err)
	}

	// Check 1: Email confirmation disabled
	if !settings.EmailConfirmRequired {
		s.reportVulnerability(result, "AUTH-001", "Email Confirmation Disabled",
			"Email confirmation is not required for new signups. This allows anyone to create accounts with unverified email addresses.",
			"MEDIUM", fmt.Sprintf("Project: %s", projectRef),
			"Enable email confirmation in Authentication > Settings > Email Auth.")
	}

	// Check 2: Phone confirmation disabled (if phone auth is used)
	if !settings.PhoneConfirmRequired {
		s.reportVulnerability(result, "AUTH-002", "Phone Confirmation Disabled",
			"Phone confirmation is not required. This allows signups with unverified phone numbers.",
			"LOW", fmt.Sprintf("Project: %s", projectRef),
			"Enable phone confirmation in Authentication > Settings > Phone Auth.")
	}

	// Check 3: Anonymous users enabled
	if settings.AnonymousUsersEnabled {
		s.reportVulnerability(result, "AUTH-003", "Anonymous Users Enabled",
			"Anonymous authentication is enabled. Ensure your RLS policies properly handle anonymous users.",
			"LOW", fmt.Sprintf("Project: %s", projectRef),
			"If anonymous users are not needed, disable them in Authentication > Settings.")
	}

	// Check 4: MFA not enabled (informational)
	if !settings.MFAEnabled {
		s.reportVulnerability(result, "MFA-001", "MFA Not Enabled",
			"Multi-factor authentication is not enabled. Consider enabling MFA for enhanced security.",
			"LOW", fmt.Sprintf("Project: %s", projectRef),
			"Enable MFA in Authentication > Settings > Multi-Factor Authentication.")
	}

	return result, nil
}

// ScanEdgeFunctions scans TypeScript/JavaScript edge function files for security issues
func (s *Scanner) ScanEdgeFunctions(ctx context.Context, repoURL string, functionsPath string) (*domain.ScanResult, error) {
	result := &domain.ScanResult{}

	// Create temp dir
	tmpDir, err := ioutil.TempDir("", "warden-edge-scan")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir)

	if err := s.gitRepo.Clone(ctx, repoURL, tmpDir); err != nil {
		return nil, err
	}

	files, err := s.gitRepo.FindEdgeFunctionFiles(tmpDir, functionsPath)
	if err != nil {
		return nil, err
	}

	// Secret patterns to detect
	secretPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)(api[_-]?key|apikey)\s*[:=]\s*['"][^'"]{10,}['"]`),
		regexp.MustCompile(`(?i)(secret|password|passwd|pwd)\s*[:=]\s*['"][^'"]{6,}['"]`),
		regexp.MustCompile(`(?i)(access[_-]?token|auth[_-]?token)\s*[:=]\s*['"][^'"]{10,}['"]`),
		regexp.MustCompile(`(?i)bearer\s+[a-zA-Z0-9_\-\.]{20,}`),
		regexp.MustCompile(`sk_live_[a-zA-Z0-9]{20,}`),
		regexp.MustCompile(`eyJ[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{20,}\.`),
	}

	for _, file := range files {
		content, err := ioutil.ReadFile(file)
		if err != nil {
			continue
		}
		contentStr := string(content)

		// EDGE-001: Check for hardcoded secrets
		for _, pattern := range secretPatterns {
			if matches := pattern.FindAllString(contentStr, -1); len(matches) > 0 {
				s.reportVulnerability(result, "EDGE-001", "Potential Hardcoded Secret",
					fmt.Sprintf("Potential hardcoded secret detected in edge function. Pattern matched: %s", pattern.String()),
					"CRITICAL", file,
					"Store secrets in environment variables or Supabase Vault. Never commit secrets to source code.")
				break
			}
		}

		// EDGE-002: Check for missing authorization header validation
		hasServeFunction := strings.Contains(contentStr, "Deno.serve") || strings.Contains(contentStr, "serve(")
		hasAuthCheck := strings.Contains(contentStr, "authorization") ||
			strings.Contains(contentStr, "Authorization") ||
			strings.Contains(contentStr, "req.headers.get") ||
			strings.Contains(contentStr, "headers.authorization") ||
			strings.Contains(contentStr, "createClient")

		if hasServeFunction && !hasAuthCheck {
			s.reportVulnerability(result, "EDGE-002", "Missing Authorization Header Validation",
				"Edge function handler does not appear to validate the Authorization header. This could allow unauthorized access.",
				"HIGH", file,
				"Verify the 'Authorization' header or create a Supabase client to validate the user token.")
		}
	}

	return result, nil
}
