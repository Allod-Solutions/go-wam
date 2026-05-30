//go:build windows && wam_integration

// Integration tests for go-wam. These tests call the real Windows WAM broker
// and require:
//
//  1. A Windows machine that is Azure AD joined
//  2. An interactive user session (not SYSTEM)
//  3. Environment variables set:
//     WAM_TEST_TENANT_ID   — Azure AD tenant GUID
//     WAM_TEST_CLIENT_ID   — app registration client ID
//
// Run with:
//
//	go test -tags wam_integration -v ./...
//
// These tests are excluded from the standard `go test ./...` run and from CI
// pipelines that don't have AAD-joined runners. They are intended to be run
// manually on a development machine or on a dedicated AAD-joined CI runner.
package wam_test

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"
)

func integrationEnv(t *testing.T) (tenantID, clientID string) {
	t.Helper()
	tenantID = os.Getenv("WAM_TEST_TENANT_ID")
	clientID = os.Getenv("WAM_TEST_CLIENT_ID")
	if tenantID == "" || clientID == "" {
		t.Skip("set WAM_TEST_TENANT_ID and WAM_TEST_CLIENT_ID to run integration tests")
	}
	return
}

func TestIntegration_GetTokenSilently(t *testing.T) {
	tenantID, clientID := integrationEnv(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	tok, err := GetTokenSilently(ctx, tenantID, clientID)
	if errors.Is(err, ErrNotAADJoined) {
		t.Skip("machine is not AAD joined — skipping")
	}
	if errors.Is(err, ErrNoAccount) {
		t.Skip("no cached WAM account — sign in interactively first")
	}
	if errors.Is(err, ErrInteractionRequired) {
		t.Skip("WAM requires user interaction — cached credential may have expired")
	}
	if err != nil {
		t.Fatalf("GetTokenSilently: %v", err)
	}

	// Basic structure check: a JWT has three base64url segments separated by dots.
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Errorf("token does not look like a JWT: %q", tok[:min(len(tok), 80)])
	}

	t.Logf("token acquired successfully (length=%d)", len(tok))
}

func TestIntegration_FindAccounts(t *testing.T) {
	tenantID, _ := integrationEnv(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	accounts, err := FindAccounts(ctx, tenantID)
	if errors.Is(err, ErrNotAADJoined) {
		t.Skip("machine is not AAD joined — skipping")
	}
	if err != nil {
		t.Fatalf("FindAccounts: %v", err)
	}

	t.Logf("found %d account(s)", len(accounts))
	for i, a := range accounts {
		t.Logf("  [%d] id=%s upn=%s", i, a.ID, a.UserName)
		if a.UserName == "" {
			t.Errorf("account[%d].UserName is empty", i)
		}
	}
}

func TestIntegration_WrongTenant(t *testing.T) {
	_, clientID := integrationEnv(t)
	wrongTenant := "00000000-0000-0000-0000-000000000000"

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := GetTokenSilently(ctx, wrongTenant, clientID)
	if err == nil {
		t.Error("expected error for wrong tenant, got nil")
	}
	t.Logf("correct error for wrong tenant: %v", err)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
