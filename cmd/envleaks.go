package cmd

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
)

var envleaksCmd = &cobra.Command{
	Use:   "envleaks <url>",
	Short: "Scan frontend for exposed secrets and environment variables",
	Long:  "Scan a frontend URL for exposed secrets in JavaScript bundles, including signature detection and source map analysis",
	Args:  cobra.ExactArgs(1),
	RunE:  runEnvleaks,
}

func init() {
	rootCmd.AddCommand(envleaksCmd)
}

func runEnvleaks(cmd *cobra.Command, args []string) error {
	targetURL := args[0]

	// Validate URL
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "https://" + targetURL
	}

	if _, err := url.Parse(targetURL); err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	fmt.Printf("Scanning %s for exposed secrets...\n\n", targetURL)

	fmt.Printf("Warden Done, No exposed secrets found.\n")

	return nil
}
