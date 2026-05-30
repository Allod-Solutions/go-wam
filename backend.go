//go:build windows

package wam

import "context"

// Backend drives token acquisition. The real implementation calls into
// WinRT/WAM; tests inject a mock via WithBackend (export_test.go).
type Backend interface {
	FindProvider(ctx context.Context, tenantID string) (ProviderHandle, error)
	FindAccount(ctx context.Context, p ProviderHandle) (AccountHandle, error)
	ListAccounts(ctx context.Context, p ProviderHandle) ([]Account, error)
	GetTokenSilently(ctx context.Context, p ProviderHandle, a AccountHandle, clientID, scope string) (idToken string, err error)
}

// ProviderHandle is a reference to a WinRT IWebAccountProvider.
// Call Release when done; the real backend holds a COM reference.
type ProviderHandle interface{ Release() }

// AccountHandle is a reference to a WinRT IWebAccount.
// Call Release when done; the real backend holds a COM reference.
type AccountHandle interface{ Release() }

var defaultBackend Backend = &realBackend{}

// realBackend is the production WinRT/WAM implementation.
type realBackend struct{}

func (b *realBackend) FindProvider(ctx context.Context, tenantID string) (ProviderHandle, error) {
	return findAADProvider(ctx, tenantID)
}

func (b *realBackend) FindAccount(ctx context.Context, p ProviderHandle) (AccountHandle, error) {
	a, err := findAccount(ctx, p.(*webAccountProvider))
	if err != nil {
		return nil, err
	}
	if a == nil {
		return nil, nil
	}
	return a, nil
}

func (b *realBackend) ListAccounts(ctx context.Context, p ProviderHandle) ([]Account, error) {
	return listAccountsFromProvider(ctx, p.(*webAccountProvider))
}

func (b *realBackend) GetTokenSilently(ctx context.Context, p ProviderHandle, a AccountHandle, clientID, scope string) (string, error) {
	req, err := newWebTokenRequest(p.(*webAccountProvider), clientID, scope)
	if err != nil {
		return "", err
	}
	defer req.release()

	result, err := getTokenSilently(ctx, req, a.(*webAccount))
	if err != nil {
		return "", err
	}
	defer result.release()

	return result.idToken()
}
