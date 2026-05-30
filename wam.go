//go:build windows

// Package wam acquires Azure AD tokens on Windows via the Web Account Manager
// (WAM) broker — the same SSO layer used by Windows itself for "Sign in with
// Microsoft". No UI is shown; the call succeeds only when the device is Azure
// AD joined and a cached credential exists for the requesting tenant.
//
// The returned token is a standard RS256-signed ID token issued by Azure AD.
// Verify it server-side via the tenant's JWKS endpoint:
//
//	https://login.microsoftonline.com/{tenantID}/v2.0/.well-known/openid-configuration
//
// Typical usage in an agent:
//
//	tok, err := wam.GetTokenSilently(ctx, tenantID, clientID)
//	if errors.Is(err, wam.ErrInteractionRequired) {
//	    // fall back to device-code / browser flow
//	}
package wam

import (
	"context"
	"errors"
	"fmt"
)

// Sentinel errors returned by this package.
var (
	// ErrNotAADJoined is returned when the device is not Azure AD joined.
	ErrNotAADJoined = errors.New("go-wam: device is not Azure AD joined")

	// ErrInteractionRequired is returned when WAM cannot acquire a token
	// silently — the user needs to complete an interactive sign-in first.
	ErrInteractionRequired = errors.New("go-wam: silent acquisition failed, user interaction required")

	// ErrNoAccount is returned when no cached WAM account matches the tenant.
	ErrNoAccount = errors.New("go-wam: no WAM account found for tenant")
)

// Account represents a cached WAM account on the device.
type Account struct {
	// ID is the WAM-internal account identifier (opaque string).
	ID string
	// UserName is the User Principal Name, e.g. "niklas@company.com".
	UserName string
}

// GetTokenSilently acquires an Azure AD ID token for the current user without
// showing any UI. It is safe to call from multiple goroutines.
//
// tenantID  — the Azure AD tenant GUID, e.g. "e1234567-..."
// clientID  — the Azure AD app registration client ID
//
// On success the returned string is a signed JWT (three base64url segments
// separated by dots) that can be verified via the tenant's JWKS endpoint.
func GetTokenSilently(ctx context.Context, tenantID, clientID string) (idToken string, err error) {
	if err := roInit(); err != nil {
		return "", fmt.Errorf("go-wam: COM init: %w", err)
	}

	provider, err := defaultBackend.FindProvider(ctx, tenantID)
	if err != nil {
		return "", err
	}
	defer provider.Release()

	account, err := defaultBackend.FindAccount(ctx, provider)
	if err != nil {
		return "", err
	}
	if account == nil {
		return "", ErrNoAccount
	}
	defer account.Release()

	return defaultBackend.GetTokenSilently(ctx, provider, account, clientID, "openid email profile")
}

// FindAccounts returns all cached WAM accounts for the given tenant.
// Useful for pre-flight checks (e.g. "is anyone signed in?").
func FindAccounts(ctx context.Context, tenantID string) ([]Account, error) {
	if err := roInit(); err != nil {
		return nil, fmt.Errorf("go-wam: COM init: %w", err)
	}

	provider, err := defaultBackend.FindProvider(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	defer provider.Release()

	return defaultBackend.ListAccounts(ctx, provider)
}
