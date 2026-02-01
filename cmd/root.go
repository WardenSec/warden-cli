package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "warden",
	Short: "Warden - A comprehensive security scanning toolkit",
	Long:  "Warden is a modular security scanning toolkit for analyzing vibecoded react and supabase applications",
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}
