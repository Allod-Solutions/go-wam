//go:build windows

package wam

import (
	"context"
	"fmt"
	"syscall"
	"unsafe"
)

// webAccountProvider wraps IWebAccountProvider.
type webAccountProvider struct{ p unsafe.Pointer }

func (p *webAccountProvider) Release() { comRelease(p.p) }

// webAccount wraps IWebAccount.
type webAccount struct{ p unsafe.Pointer }

func (a *webAccount) Release() { comRelease(a.p) }

// userName calls IWebAccount::get_UserName → HSTRING.
func (a *webAccount) userName() (string, error) {
	vtbl := *(*[32]uintptr)(a.p)
	var hs hstring
	hr, _, _ := syscall.SyscallN(vtbl[vtblGetWebAccountUserName],
		uintptr(a.p),
		uintptr(unsafe.Pointer(&hs)),
	)
	if hr != 0 {
		return "", hresultError("IWebAccount::get_UserName", hr)
	}
	defer hs.delete()
	return hs.String(), nil
}

// id calls IWebAccount::get_Id → HSTRING.
func (a *webAccount) id() (string, error) {
	vtbl := *(*[32]uintptr)(a.p)
	var hs hstring
	hr, _, _ := syscall.SyscallN(vtbl[vtblGetWebAccountId],
		uintptr(a.p),
		uintptr(unsafe.Pointer(&hs)),
	)
	if hr != 0 {
		return "", hresultError("IWebAccount::get_Id", hr)
	}
	defer hs.delete()
	return hs.String(), nil
}

// findAADProvider calls IWebAuthenticationCoreManagerStatics::
// FindAccountProviderAsync with the Microsoft AAD provider ID and the tenant
// as authority, then waits for the result.
func findAADProvider(ctx context.Context, tenantID string) (*webAccountProvider, error) {
	factory, err := roGetActivationFactory(
		"Windows.Security.Authentication.Web.Core.WebAuthenticationCoreManager",
		iidWebAuthCoreManagerStatics,
	)
	if err != nil {
		return nil, fmt.Errorf("go-wam: get factory: %w", err)
	}
	defer comRelease(factory)

	providerIDHStr, err := newHString("https://login.microsoft.com")
	if err != nil {
		return nil, err
	}
	defer providerIDHStr.delete()

	// Authority is the tenant-specific endpoint; this scopes the provider to
	// the requested tenant and is what makes IWA tenant-aware.
	authority := fmt.Sprintf("https://login.microsoftonline.com/%s", tenantID)
	authorityHStr, err := newHString(authority)
	if err != nil {
		return nil, err
	}
	defer authorityHStr.delete()

	vtbl := *(*[32]uintptr)(factory)
	var asyncOp unsafe.Pointer
	hr, _, _ := syscall.SyscallN(vtbl[vtblFindAccountProviderWithAuthority],
		uintptr(factory),
		uintptr(providerIDHStr),
		uintptr(authorityHStr),
		uintptr(unsafe.Pointer(&asyncOp)),
	)
	if hr != 0 {
		return nil, hresultError("FindAccountProviderAsync", hr)
	}
	defer comRelease(asyncOp)

	if err := pollAsync(ctx, asyncOp); err != nil {
		return nil, fmt.Errorf("go-wam: find provider: %w", err)
	}

	result, err := asyncGetResults(asyncOp)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, ErrNotAADJoined
	}
	return &webAccountProvider{p: result}, nil
}

// findAccount calls FindAllAccountsAsync to get the first cached WAM account
// for the provider. Returns nil (no error) when no account is cached.
func findAccount(ctx context.Context, provider *webAccountProvider) (*webAccount, error) {
	accounts, err := listAccountPtrs(ctx, provider)
	if err != nil {
		return nil, err
	}
	if len(accounts) == 0 {
		return nil, nil
	}
	// Use the first account; multiple accounts = user has multiple AAD profiles.
	for i := 1; i < len(accounts); i++ {
		comRelease(accounts[i])
	}
	return &webAccount{p: accounts[0]}, nil
}

func listAccountsFromProvider(ctx context.Context, provider *webAccountProvider) ([]Account, error) {
	ptrs, err := listAccountPtrs(ctx, provider)
	if err != nil {
		return nil, err
	}
	accounts := make([]Account, 0, len(ptrs))
	for _, p := range ptrs {
		a := &webAccount{p: p}
		upn, _ := a.userName()
		id, _ := a.id()
		accounts = append(accounts, Account{ID: id, UserName: upn})
		a.Release()
	}
	return accounts, nil
}

// listAccountPtrs calls FindAllAccountsAsync and unwraps the result into raw
// IWebAccount COM pointers. Each returned pointer must be comRelease-d by the caller.
//
// The async result is IFindAllAccountsResult (IID a5812b5d-…), whose vtable layout:
//
//	[iinspectableBase+0] get_Accounts   → IVectorView<IWebAccount>
//	[iinspectableBase+1] get_Status     → FindAllWebAccountsStatus enum
//	[iinspectableBase+2] get_ProviderError → IWebProviderError
func listAccountPtrs(ctx context.Context, provider *webAccountProvider) ([]unsafe.Pointer, error) {
	factory, err := roGetActivationFactory(
		"Windows.Security.Authentication.Web.Core.WebAuthenticationCoreManager",
		iidWebAuthCoreManagerStatics,
	)
	if err != nil {
		return nil, err
	}
	defer comRelease(factory)

	vtbl := *(*[32]uintptr)(factory)
	var asyncOp unsafe.Pointer
	hr, _, _ := syscall.SyscallN(vtbl[vtblFindAllAccounts],
		uintptr(factory),
		uintptr(provider.p),
		uintptr(unsafe.Pointer(&asyncOp)),
	)
	if hr != 0 {
		return nil, hresultError("FindAllAccountsAsync", hr)
	}
	defer comRelease(asyncOp)

	if err := pollAsync(ctx, asyncOp); err != nil {
		return nil, fmt.Errorf("go-wam: find accounts: %w", err)
	}

	// GetResults → IFindAllAccountsResult
	findResult, err := asyncGetResults(asyncOp)
	if err != nil {
		return nil, err
	}
	if findResult == nil {
		return nil, nil
	}
	defer comRelease(findResult)

	// Check status before accessing accounts.
	findResultVtbl := *(*[32]uintptr)(findResult)
	var status uint32
	hr, _, _ = syscall.SyscallN(findResultVtbl[vtblFindAllResultGetStatus],
		uintptr(findResult),
		uintptr(unsafe.Pointer(&status)),
	)
	if hr != 0 {
		return nil, hresultError("IFindAllAccountsResult::get_Status", hr)
	}
	if status != findAllWebAccountsSuccess {
		// NotAllowed (1): app lacks permission to enumerate accounts; treat as empty.
		return nil, nil
	}

	// get_Accounts → IVectorView<IWebAccount>
	var accountsVec unsafe.Pointer
	hr, _, _ = syscall.SyscallN(findResultVtbl[vtblFindAllResultGetAccounts],
		uintptr(findResult),
		uintptr(unsafe.Pointer(&accountsVec)),
	)
	if hr != 0 {
		return nil, hresultError("IFindAllAccountsResult::get_Accounts", hr)
	}
	if accountsVec == nil {
		return nil, nil
	}
	defer comRelease(accountsVec)

	// IVectorView::get_Size
	vecVtbl := *(*[32]uintptr)(accountsVec)
	var size uint32
	hr, _, _ = syscall.SyscallN(vecVtbl[vtblVectorViewSize],
		uintptr(accountsVec),
		uintptr(unsafe.Pointer(&size)),
	)
	if hr != 0 {
		return nil, hresultError("IVectorView::get_Size", hr)
	}

	// IVectorView::GetAt(i) for each account
	ptrs := make([]unsafe.Pointer, 0, size)
	for i := uint32(0); i < size; i++ {
		var account unsafe.Pointer
		hr, _, _ = syscall.SyscallN(vecVtbl[vtblVectorViewGetAt],
			uintptr(accountsVec),
			uintptr(i),
			uintptr(unsafe.Pointer(&account)),
		)
		if hr != 0 {
			for _, p := range ptrs {
				comRelease(p)
			}
			return nil, hresultError("IVectorView::GetAt", hr)
		}
		if account != nil {
			ptrs = append(ptrs, account)
		}
	}
	return ptrs, nil
}
