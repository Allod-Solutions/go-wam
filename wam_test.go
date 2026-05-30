//go:build windows

package wam_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/myrstack/go-wam"
	"github.com/myrstack/go-wam/internal/testbackend"
)

// ── mock plumbing ─────────────────────────────────────────────────────────────

// The test suite uses testbackend.Mock, which implements wam.Backend and is
// injected via wam.WithBackend (exported only in test builds via export_test.go).
// This lets us cover every branch of the public API without a real Windows AAD
// environment or COM/WinRT calls.

// ── GetTokenSilently ──────────────────────────────────────────────────────────

func TestGetTokenSilently_HappyPath(t *testing.T) {
	const (
		tenantID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
		clientID = "11111111-2222-3333-4444-555555555555"
		upn      = "niklas@company.com"
		wantTok  = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.signature"
	)

	mock := testbackend.New().
		WithProvider(tenantID).
		WithAccount(tenantID, upn).
		WithToken(tenantID, clientID, wantTok)

	wam.WithBackend(mock)
	t.Cleanup(func() { wam.WithBackend(nil) })

	tok, err := wam.GetTokenSilently(context.Background(), tenantID, clientID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok != wantTok {
		t.Errorf("token = %q, want %q", tok, wantTok)
	}
}

func TestGetTokenSilently_DeviceNotAADJoined(t *testing.T) {
	mock := testbackend.New() // no provider configured → not AAD joined

	wam.WithBackend(mock)
	t.Cleanup(func() { wam.WithBackend(nil) })

	_, err := wam.GetTokenSilently(context.Background(), "any-tenant", "any-client")
	if !errors.Is(err, wam.ErrNotAADJoined) {
		t.Errorf("err = %v, want ErrNotAADJoined", err)
	}
}

func TestGetTokenSilently_NoAccount(t *testing.T) {
	const tenantID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

	mock := testbackend.New().
		WithProvider(tenantID) // provider exists but no cached account

	wam.WithBackend(mock)
	t.Cleanup(func() { wam.WithBackend(nil) })

	_, err := wam.GetTokenSilently(context.Background(), tenantID, "any-client")
	if !errors.Is(err, wam.ErrNoAccount) {
		t.Errorf("err = %v, want ErrNoAccount", err)
	}
}

func TestGetTokenSilently_InteractionRequired(t *testing.T) {
	const (
		tenantID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
		clientID = "11111111-2222-3333-4444-555555555555"
	)

	mock := testbackend.New().
		WithProvider(tenantID).
		WithAccount(tenantID, "user@company.com").
		WithTokenError(tenantID, clientID, wam.ErrInteractionRequired)

	wam.WithBackend(mock)
	t.Cleanup(func() { wam.WithBackend(nil) })

	_, err := wam.GetTokenSilently(context.Background(), tenantID, clientID)
	if !errors.Is(err, wam.ErrInteractionRequired) {
		t.Errorf("err = %v, want ErrInteractionRequired", err)
	}
}

func TestGetTokenSilently_ContextCanceled(t *testing.T) {
	const tenantID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

	// Block the provider lookup until the context is canceled.
	mock := testbackend.New().
		WithProvider(tenantID).
		WithProviderDelay(tenantID, 10*time.Second) // longer than the test timeout

	wam.WithBackend(mock)
	t.Cleanup(func() { wam.WithBackend(nil) })

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := wam.GetTokenSilently(ctx, tenantID, "any-client")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want DeadlineExceeded", err)
	}
}

func TestGetTokenSilently_WrongTenant_NoProvider(t *testing.T) {
	const configuredTenant = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	const requestedTenant  = "11111111-2222-3333-4444-555555555555"

	mock := testbackend.New().
		WithProvider(configuredTenant). // device is joined to a different tenant
		WithAccount(configuredTenant, "user@company.com")

	wam.WithBackend(mock)
	t.Cleanup(func() { wam.WithBackend(nil) })

	_, err := wam.GetTokenSilently(context.Background(), requestedTenant, "any-client")
	if !errors.Is(err, wam.ErrNotAADJoined) {
		t.Errorf("err = %v, want ErrNotAADJoined", err)
	}
}

func TestGetTokenSilently_EmptyTokenFromWAM(t *testing.T) {
	const (
		tenantID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
		clientID = "11111111-2222-3333-4444-555555555555"
	)

	mock := testbackend.New().
		WithProvider(tenantID).
		WithAccount(tenantID, "user@company.com").
		WithToken(tenantID, clientID, "") // WAM returns empty string

	wam.WithBackend(mock)
	t.Cleanup(func() { wam.WithBackend(nil) })

	_, err := wam.GetTokenSilently(context.Background(), tenantID, clientID)
	if err == nil {
		t.Error("expected error for empty token, got nil")
	}
}

// ── FindAccounts ──────────────────────────────────────────────────────────────

func TestFindAccounts_ReturnsAll(t *testing.T) {
	const tenantID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

	mock := testbackend.New().
		WithProvider(tenantID).
		WithAccount(tenantID, "alice@company.com").
		WithAccount(tenantID, "bob@company.com")

	wam.WithBackend(mock)
	t.Cleanup(func() { wam.WithBackend(nil) })

	accounts, err := wam.FindAccounts(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(accounts) != 2 {
		t.Fatalf("got %d accounts, want 2", len(accounts))
	}
	names := map[string]bool{accounts[0].UserName: true, accounts[1].UserName: true}
	for _, want := range []string{"alice@company.com", "bob@company.com"} {
		if !names[want] {
			t.Errorf("account %q not found in results", want)
		}
	}
}

func TestFindAccounts_NoProvider(t *testing.T) {
	mock := testbackend.New()

	wam.WithBackend(mock)
	t.Cleanup(func() { wam.WithBackend(nil) })

	_, err := wam.FindAccounts(context.Background(), "any-tenant")
	if !errors.Is(err, wam.ErrNotAADJoined) {
		t.Errorf("err = %v, want ErrNotAADJoined", err)
	}
}

func TestFindAccounts_NoAccounts(t *testing.T) {
	const tenantID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"

	mock := testbackend.New().
		WithProvider(tenantID) // provider exists, no accounts

	wam.WithBackend(mock)
	t.Cleanup(func() { wam.WithBackend(nil) })

	accounts, err := wam.FindAccounts(context.Background(), tenantID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(accounts) != 0 {
		t.Errorf("got %d accounts, want 0", len(accounts))
	}
}
