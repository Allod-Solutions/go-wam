//go:build windows

// Package testbackend provides a configurable mock WAM backend for use in
// tests. It implements wam.Backend without making any Win32 or COM calls,
// so it runs on any Windows machine (no AAD join required).
package testbackend

import (
	"context"
	"fmt"
	"time"

	"github.com/Allod-Solutions/go-wam"
)

// mockProvider is a ProviderHandle backed by in-memory state.
type mockProvider struct{ tenantID string }

func (p *mockProvider) Release() {}

// mockAccount is an AccountHandle backed by in-memory state.
type mockAccount struct{ upn string }

func (a *mockAccount) Release() {}

// Mock is a configurable wam.Backend that records state set up via the
// builder methods. All methods are safe to call from multiple goroutines.
type Mock struct {
	providers      map[string]bool       // tenantID → exists
	providerDelays map[string]time.Duration
	accounts       map[string][]string   // tenantID → []upn
	tokens         map[string]string     // tenantID+":"+clientID → idToken
	tokenErrors    map[string]error      // tenantID+":"+clientID → error
}

// New returns an empty Mock with no providers, accounts, or tokens configured.
func New() *Mock {
	return &Mock{
		providers:      make(map[string]bool),
		providerDelays: make(map[string]time.Duration),
		accounts:       make(map[string][]string),
		tokens:         make(map[string]string),
		tokenErrors:    make(map[string]error),
	}
}

// WithProvider configures the mock to report that the device is joined to the
// given tenant (i.e. FindProvider will succeed for that tenantID).
func (m *Mock) WithProvider(tenantID string) *Mock {
	m.providers[tenantID] = true
	return m
}

// WithProviderDelay makes FindProvider for tenantID block for d before
// returning, so context-cancellation paths can be tested.
func (m *Mock) WithProviderDelay(tenantID string, d time.Duration) *Mock {
	m.providerDelays[tenantID] = d
	return m
}

// WithAccount adds a cached WAM account for tenantID with the given UPN.
// Multiple calls add multiple accounts (same tenant, different users).
func (m *Mock) WithAccount(tenantID, upn string) *Mock {
	m.accounts[tenantID] = append(m.accounts[tenantID], upn)
	return m
}

// WithToken configures the token that GetTokenSilently returns for the given
// (tenantID, clientID) pair.
func (m *Mock) WithToken(tenantID, clientID, idToken string) *Mock {
	m.tokens[tokenKey(tenantID, clientID)] = idToken
	return m
}

// WithTokenError configures GetTokenSilently to return err for (tenantID, clientID).
func (m *Mock) WithTokenError(tenantID, clientID string, err error) *Mock {
	m.tokenErrors[tokenKey(tenantID, clientID)] = err
	return m
}

// ── wam.Backend implementation ────────────────────────────────────────────────

func (m *Mock) FindProvider(ctx context.Context, tenantID string) (wam.ProviderHandle, error) {
	if d := m.providerDelays[tenantID]; d > 0 {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(d):
		}
	}
	if !m.providers[tenantID] {
		return nil, wam.ErrNotAADJoined
	}
	return &mockProvider{tenantID: tenantID}, nil
}

func (m *Mock) FindAccount(ctx context.Context, p wam.ProviderHandle) (wam.AccountHandle, error) {
	mp := p.(*mockProvider)
	upns := m.accounts[mp.tenantID]
	if len(upns) == 0 {
		return nil, nil
	}
	return &mockAccount{upn: upns[0]}, nil
}

func (m *Mock) ListAccounts(ctx context.Context, p wam.ProviderHandle) ([]wam.Account, error) {
	mp := p.(*mockProvider)
	upns := m.accounts[mp.tenantID]
	accounts := make([]wam.Account, len(upns))
	for i, upn := range upns {
		accounts[i] = wam.Account{ID: fmt.Sprintf("mock-id-%d", i), UserName: upn}
	}
	return accounts, nil
}

func (m *Mock) GetTokenSilently(ctx context.Context, p wam.ProviderHandle, a wam.AccountHandle, clientID, scope string) (string, error) {
	mp := p.(*mockProvider)
	key := tokenKey(mp.tenantID, clientID)
	if err, ok := m.tokenErrors[key]; ok {
		return "", err
	}
	tok, ok := m.tokens[key]
	if !ok {
		return "", fmt.Errorf("testbackend: no token configured for tenant=%s client=%s", mp.tenantID, clientID)
	}
	if tok == "" {
		return "", fmt.Errorf("go-wam: WAM returned empty token")
	}
	return tok, nil
}

func tokenKey(tenantID, clientID string) string {
	return tenantID + ":" + clientID
}
