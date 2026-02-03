package git

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5"
)

type GitRepository struct{}

func NewGitRepository() *GitRepository {
	return &GitRepository{}
}

func (r *GitRepository) Clone(ctx context.Context, url string, dest string) error {
	_, err := git.PlainCloneContext(ctx, dest, false, &git.CloneOptions{
		URL:      url,
		Progress: os.Stderr, // Use stderr so JSON output goes to stdout cleanly
	})
	return err
}

func (r *GitRepository) FindMigrationFiles(dir string, subDir string) ([]string, error) {
	var files []string
	// Combine the temp/cloned dir with the requested subdirectory
	searchPath := filepath.Join(dir, subDir)

	err := filepath.Walk(searchPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(info.Name(), ".sql") {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}

func (r *GitRepository) FindEdgeFunctionFiles(dir string, subDir string) ([]string, error) {
	var files []string
	searchPath := filepath.Join(dir, subDir)

	err := filepath.Walk(searchPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			// Directory doesn't exist is not an error for edge functions
			if os.IsNotExist(err) {
				return nil
			}
			return err
		}
		if !info.IsDir() && (strings.HasSuffix(info.Name(), ".ts") || strings.HasSuffix(info.Name(), ".js")) {
			files = append(files, path)
		}
		return nil
	})
	if os.IsNotExist(err) {
		return nil, nil
	}
	return files, err
}
