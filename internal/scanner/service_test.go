package scanner_test

import (
	"context"
	"io/ioutil"
	"os"
	"testing"
	"warden/cli/internal/domain"
	"warden/cli/internal/scanner"

	pg_query "github.com/pganalyze/pg_query_go/v5"
)

// MockDatabaseRepository implements domain.DatabaseRepository for testing
type MockDatabaseRepository struct {
	tables          []string
	policies        []domain.Policy
	functions       []domain.Function
	buckets         []domain.Bucket
	storagePolicies []domain.StoragePolicy
	roleGrants      []domain.RoleGrant
	connectErr      error
}

func (m *MockDatabaseRepository) Connect(ctx context.Context, connectionString string) error {
	return m.connectErr
}
func (m *MockDatabaseRepository) Close(ctx context.Context) error { return nil }
func (m *MockDatabaseRepository) GetTablesWithoutRLS(ctx context.Context) ([]string, error) {
	return m.tables, nil
}
func (m *MockDatabaseRepository) GetPolicies(ctx context.Context) ([]domain.Policy, error) {
	return m.policies, nil
}
func (m *MockDatabaseRepository) GetInsecureFunctions(ctx context.Context) ([]domain.Function, error) {
	return m.functions, nil
}
func (m *MockDatabaseRepository) GetPublicBuckets(ctx context.Context) ([]domain.Bucket, error) {
	return m.buckets, nil
}
func (m *MockDatabaseRepository) GetStoragePolicies(ctx context.Context) ([]domain.StoragePolicy, error) {
	return m.storagePolicies, nil
}
func (m *MockDatabaseRepository) GetRoleGrants(ctx context.Context) ([]domain.RoleGrant, error) {
	return m.roleGrants, nil
}

// MockGitRepository implements domain.GitRepository for testing
type MockGitRepository struct {
	files             []string
	edgeFunctionFiles []string
}

func (m *MockGitRepository) Clone(ctx context.Context, url string, dest string) error {
	return nil
}
func (m *MockGitRepository) FindMigrationFiles(dir string, subDir string) ([]string, error) {
	return m.files, nil
}
func (m *MockGitRepository) FindEdgeFunctionFiles(dir string, subDir string) ([]string, error) {
	return m.edgeFunctionFiles, nil
}

// MockSQLParser implements domain.SQLParser for testing
type MockSQLParser struct {
	results map[string]*pg_query.ParseResult
}

func (m *MockSQLParser) Parse(sql string) (interface{}, error) {
	if res, ok := m.results[sql]; ok {
		return res, nil
	}
	return &pg_query.ParseResult{}, nil
}

// MockManagementAPI implements domain.ManagementAPI for testing
type MockManagementAPI struct {
	settings *domain.ProjectSettings
	err      error
}

func (m *MockManagementAPI) GetProjectSettings(ctx context.Context, projectRef, accessToken string) (*domain.ProjectSettings, error) {
	return m.settings, m.err
}

func TestScanLive_DetectsTablesWithoutRLS(t *testing.T) {
	dbRepo := &MockDatabaseRepository{
		tables: []string{"public.users", "public.orders"},
	}
	s := scanner.NewScanner(dbRepo, &MockGitRepository{}, &MockManagementAPI{}, &MockSQLParser{}, domain.WardenConfig{})

	result, err := s.ScanLive(context.Background(), "mock://db")
	if err != nil {
		t.Fatalf("ScanLive failed: %v", err)
	}

	if len(result.Vulnerabilities) != 2 {
		t.Errorf("Expected 2 RLS-001 vulnerabilities, got %d", len(result.Vulnerabilities))
	}

	for _, v := range result.Vulnerabilities {
		if v.ID != "RLS-001" {
			t.Errorf("Expected RLS-001, got %s", v.ID)
		}
	}
}

func TestScanLive_DetectsPermissivePolicies(t *testing.T) {
	dbRepo := &MockDatabaseRepository{
		policies: []domain.Policy{
			{
				Name:      "Allow All",
				TableName: "users",
				Schema:    "public",
				Roles:     []string{"anon"},
				Qual:      "true",
			},
		},
	}
	s := scanner.NewScanner(dbRepo, &MockGitRepository{}, &MockManagementAPI{}, &MockSQLParser{}, domain.WardenConfig{})

	result, err := s.ScanLive(context.Background(), "mock://db")
	if err != nil {
		t.Fatalf("ScanLive failed: %v", err)
	}

	found := false
	for _, v := range result.Vulnerabilities {
		if v.ID == "POL-002" {
			found = true
		}
	}
	if !found {
		t.Error("Expected to find POL-002 vulnerability")
	}
}

func TestScanLive_DetectsInsecureFunctions(t *testing.T) {
	dbRepo := &MockDatabaseRepository{
		functions: []domain.Function{
			{
				Schema:            "public",
				Name:              "get_admin_data",
				IsSecurityDefiner: true,
				SearchPath:        "",
			},
		},
	}
	s := scanner.NewScanner(dbRepo, &MockGitRepository{}, &MockManagementAPI{}, &MockSQLParser{}, domain.WardenConfig{})

	result, err := s.ScanLive(context.Background(), "mock://db")
	if err != nil {
		t.Fatalf("ScanLive failed: %v", err)
	}

	found := false
	for _, v := range result.Vulnerabilities {
		if v.ID == "FUNC-001" {
			found = true
		}
	}
	if !found {
		t.Error("Expected to find FUNC-001 vulnerability")
	}
}

func TestScanLive_DetectsPublicBuckets(t *testing.T) {
	dbRepo := &MockDatabaseRepository{
		buckets: []domain.Bucket{
			{ID: "1", Name: "avatars", IsPublic: true},
		},
	}
	s := scanner.NewScanner(dbRepo, &MockGitRepository{}, &MockManagementAPI{}, &MockSQLParser{}, domain.WardenConfig{})

	result, err := s.ScanLive(context.Background(), "mock://db")
	if err != nil {
		t.Fatalf("ScanLive failed: %v", err)
	}

	found := false
	for _, v := range result.Vulnerabilities {
		if v.ID == "STOR-001" {
			found = true
		}
	}
	if !found {
		t.Error("Expected to find STOR-001 vulnerability")
	}
}

func TestScanAPI_DetectsMisconfigurations(t *testing.T) {
	apiRepo := &MockManagementAPI{
		settings: &domain.ProjectSettings{
			EmailConfirmRequired:  false,
			PhoneConfirmRequired:  false,
			AnonymousUsersEnabled: true,
			MFAEnabled:            false,
		},
	}
	s := scanner.NewScanner(&MockDatabaseRepository{}, &MockGitRepository{}, apiRepo, &MockSQLParser{}, domain.WardenConfig{})

	result, err := s.ScanAPI(context.Background(), "ref", "token")
	if err != nil {
		t.Fatalf("ScanAPI failed: %v", err)
	}

	expectedIDs := map[string]bool{
		"AUTH-001": true,
		"AUTH-002": true,
		"AUTH-003": true,
		"MFA-001":  true,
	}

	foundCount := 0
	for _, v := range result.Vulnerabilities {
		if expectedIDs[v.ID] {
			foundCount++
		}
	}

	if foundCount != 4 {
		t.Errorf("Expected 4 vulnerabilities from API scan, got %d", foundCount)
	}
}

func TestScanStatic_DetectsStaticIssues(t *testing.T) {
	// To test ScanStatic, we'll use a real temp file since it uses ioutil.ReadFile
	tmpFile, err := ioutil.TempFile("", "test-migration-*.sql")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	sql := "CREATE TABLE users();"
	if _, err := tmpFile.Write([]byte(sql)); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	tmpFile.Close()

	gitRepo := &MockGitRepository{
		files: []string{tmpFile.Name()},
	}

	parser := &MockSQLParser{
		results: map[string]*pg_query.ParseResult{
			sql: {
				Stmts: []*pg_query.RawStmt{
					{
						Stmt: &pg_query.Node{
							Node: &pg_query.Node_CreateStmt{
								CreateStmt: &pg_query.CreateStmt{
									Relation: &pg_query.RangeVar{
										Relname: "users",
									},
								},
							},
						},
					},
				},
			},
		},
	}

	s := scanner.NewScanner(&MockDatabaseRepository{}, gitRepo, &MockManagementAPI{}, parser, domain.WardenConfig{})

	// Test 2: Permissive Policy (POL-003)
	sql2 := "CREATE POLICY \"Allow All\" ON users FOR SELECT TO public USING (true);"
	tmpFile2, _ := ioutil.TempFile("", "test-migration-2-*.sql")
	tmpFile2.Write([]byte(sql2))
	tmpFile2.Close()
	defer os.Remove(tmpFile2.Name())

	// Test 3: Insecure Function (FUNC-002)
	sql3 := "CREATE FUNCTION get_data() RETURNS void SECURITY DEFINER AS $$ $$;"
	tmpFile3, _ := ioutil.TempFile("", "test-migration-3-*.sql")
	tmpFile3.Write([]byte(sql3))
	tmpFile3.Close()
	defer os.Remove(tmpFile3.Name())

	gitRepo.files = append(gitRepo.files, tmpFile2.Name(), tmpFile3.Name())

	parser.results[sql2] = &pg_query.ParseResult{
		Stmts: []*pg_query.RawStmt{
			{
				Stmt: &pg_query.Node{
					Node: &pg_query.Node_CreatePolicyStmt{
						CreatePolicyStmt: &pg_query.CreatePolicyStmt{
							PolicyName: "Allow All",
							Roles: []*pg_query.Node{
								{
									Node: &pg_query.Node_RoleSpec{
										RoleSpec: &pg_query.RoleSpec{
											Roletype: pg_query.RoleSpecType_ROLESPEC_PUBLIC,
										},
									},
								},
							},
							Qual: &pg_query.Node{
								Node: &pg_query.Node_AConst{
									AConst: &pg_query.A_Const{
										Val: &pg_query.A_Const_Boolval{
											Boolval: &pg_query.Boolean{
												Boolval: true,
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	parser.results[sql3] = &pg_query.ParseResult{
		Stmts: []*pg_query.RawStmt{
			{
				Stmt: &pg_query.Node{
					Node: &pg_query.Node_CreateFunctionStmt{
						CreateFunctionStmt: &pg_query.CreateFunctionStmt{
							Funcname: []*pg_query.Node{
								{
									Node: &pg_query.Node_String_{
										String_: &pg_query.String{
											Sval: "get_data",
										},
									},
								},
							},
							Options: []*pg_query.Node{
								{
									Node: &pg_query.Node_DefElem{
										DefElem: &pg_query.DefElem{
											Defname: "security",
											Arg: &pg_query.Node{
												Node: &pg_query.Node_Boolean{
													Boolean: &pg_query.Boolean{
														Boolval: true,
													},
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	result, err := s.ScanStatic(context.Background(), ".", ".")
	if err != nil {
		t.Fatalf("ScanStatic failed: %v", err)
	}

	foundRLS := false
	foundPOL := false
	foundFUNC := false
	for _, v := range result.Vulnerabilities {
		if v.ID == "RLS-002" {
			foundRLS = true
		}
		if v.ID == "POL-003" {
			foundPOL = true
		}
		if v.ID == "FUNC-002" {
			foundFUNC = true
		}
	}

	if !foundRLS {
		t.Error("Expected to find RLS-002 (Missing RLS)")
	}
	if !foundPOL {
		t.Error("Expected to find POL-003 (Permissive Policy)")
	}
	if !foundFUNC {
		t.Error("Expected to find FUNC-002 (Insecure Function)")
	}
}
