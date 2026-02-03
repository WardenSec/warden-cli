package supabase

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"warden/internal/domain"
)

// ManagementClient interacts with the Supabase Management API.
type ManagementClient struct {
	accessToken string
	httpClient  *http.Client
	baseURL     string
}

// NewManagementClient creates a new Supabase Management API client.
func NewManagementClient(accessToken string) *ManagementClient {
	return &ManagementClient{
		accessToken: accessToken,
		httpClient:  &http.Client{},
		baseURL:     "https://api.supabase.com/v1",
	}
}

// GetProjectSettings retrieves security-relevant settings for a project.
func (c *ManagementClient) GetProjectSettings(ctx context.Context, projectRef, accessToken string) (*domain.ProjectSettings, error) {
	// Update accessToken if provided
	if accessToken != "" {
		c.accessToken = accessToken
	}
	// Get Auth config
	authConfig, err := c.getAuthConfig(ctx, projectRef)
	if err != nil {
		return nil, fmt.Errorf("failed to get auth config: %w", err)
	}

	settings := &domain.ProjectSettings{}

	// Parse auth config
	if siteURL, ok := authConfig["site_url"].(string); ok {
		_ = siteURL // Available for future checks
	}

	// Check email confirmation
	if mailer, ok := authConfig["mailer"].(map[string]interface{}); ok {
		if autoConfirm, ok := mailer["autoconfirm"].(bool); ok {
			settings.EmailConfirmRequired = !autoConfirm
		}
	}

	// Check phone confirmation
	if sms, ok := authConfig["sms"].(map[string]interface{}); ok {
		if autoConfirm, ok := sms["autoconfirm"].(bool); ok {
			settings.PhoneConfirmRequired = !autoConfirm
		}
	}

	// Check external anonymous users
	if external, ok := authConfig["external"].(map[string]interface{}); ok {
		if anonymous, ok := external["anonymous_users"].(map[string]interface{}); ok {
			if enabled, ok := anonymous["enabled"].(bool); ok {
				settings.AnonymousUsersEnabled = enabled
			}
		}
	}

	// Check MFA
	if security, ok := authConfig["security"].(map[string]interface{}); ok {
		if mfa, ok := security["mfa"].(map[string]interface{}); ok {
			if enabled, ok := mfa["enabled"].(bool); ok {
				settings.MFAEnabled = enabled
			}
		}
	}

	return settings, nil
}

func (c *ManagementClient) getAuthConfig(ctx context.Context, projectRef string) (map[string]interface{}, error) {
	url := fmt.Sprintf("%s/projects/%s/config/auth", c.baseURL, projectRef)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", c.accessToken))
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	var config map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&config); err != nil {
		return nil, err
	}

	return config, nil
}
