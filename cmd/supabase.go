/*
Copyright © 2026 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// supabaseCmd represents the supabase command
var supabaseCmd = &cobra.Command{
	Use:   "supabase",
	Short: "Scan Supabase projects for security issues",
	Long:  `Long description`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("supabase called")
	},
}

func init() {
	rootCmd.AddCommand(supabaseCmd)
}
