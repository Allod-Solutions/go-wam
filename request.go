//go:build windows

package wam

import (
	"context"
	"fmt"
	"syscall"
	"unsafe"
)

// webTokenRequest wraps IWebTokenRequest.
type webTokenRequest struct{ p unsafe.Pointer }

func (r *webTokenRequest) release() { comRelease(r.p) }

// webTokenRequestResult wraps IWebTokenRequestResult.
type webTokenRequestResult struct{ p unsafe.Pointer }

func (r *webTokenRequestResult) release() { comRelease(r.p) }

// newWebTokenRequest creates a WebTokenRequest via IWebTokenRequestFactory.
// scope is a space-separated list of OIDC scopes, e.g. "openid email profile".
func newWebTokenRequest(provider *webAccountProvider, clientID, scope string) (*webTokenRequest, error) {
	factory, err := roGetActivationFactory(
		"Windows.Security.Authentication.Web.Core.WebTokenRequest",
		iidWebTokenRequestFactory,
	)
	if err != nil {
		return nil, fmt.Errorf("get WebTokenRequest factory: %w", err)
	}
	defer comRelease(factory)

	clientIDHStr, err := newHString(clientID)
	if err != nil {
		return nil, err
	}
	defer clientIDHStr.delete()

	scopeHStr, err := newHString(scope)
	if err != nil {
		return nil, err
	}
	defer scopeHStr.delete()

	// WebTokenRequestPromptType: SilentlyPreferred = 1 (try silent, show UI only if needed)
	// We use 0 (Silent) to enforce no-UI — return error if interaction required.
	const promptTypeSilent = 0

	vtbl := *(*[32]uintptr)(factory)
	var req unsafe.Pointer
	hr, _, _ := syscall.SyscallN(vtbl[vtblCreateWebTokenRequest],
		uintptr(factory),
		uintptr(provider.p),
		uintptr(scopeHStr),
		uintptr(clientIDHStr),
		uintptr(promptTypeSilent),
		uintptr(unsafe.Pointer(&req)),
	)
	if hr != 0 {
		return nil, hresultError("IWebTokenRequestFactory::CreateWithProviderAndScope", hr)
	}
	return &webTokenRequest{p: req}, nil
}

// getTokenSilently calls IWebAuthenticationCoreManagerStatics::
// GetTokenSilentlyAsync with a specific account and waits for the result.
func getTokenSilently(ctx context.Context, req *webTokenRequest, account *webAccount) (*webTokenRequestResult, error) {
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
	hr, _, _ := syscall.SyscallN(vtbl[vtblGetTokenSilentlyWithAccount],
		uintptr(factory),
		uintptr(req.p),
		uintptr(account.p),
		uintptr(unsafe.Pointer(&asyncOp)),
	)
	if hr != 0 {
		return nil, hresultError("GetTokenSilentlyAsync", hr)
	}
	defer comRelease(asyncOp)

	if err := pollAsync(ctx, asyncOp); err != nil {
		return nil, fmt.Errorf("go-wam: get token: %w", err)
	}

	result, err := asyncGetResults(asyncOp)
	if err != nil {
		return nil, err
	}
	return &webTokenRequestResult{p: result}, nil
}

// idToken extracts the ID token string from the request result.
// Returns ErrInteractionRequired when the WAM response status indicates that
// the user must complete an interactive sign-in.
func (r *webTokenRequestResult) idToken() (string, error) {
	vtbl := *(*[32]uintptr)(r.p)

	// get_ResponseStatus → WebTokenRequestStatus enum
	var status uint32
	hr, _, _ := syscall.SyscallN(vtbl[vtblGetResponseStatus],
		uintptr(r.p),
		uintptr(unsafe.Pointer(&status)),
	)
	if hr != 0 {
		return "", hresultError("IWebTokenRequestResult::get_ResponseStatus", hr)
	}

	switch status {
	case webTokenRequestStatusUserInteractionRequired:
		return "", ErrInteractionRequired
	case webTokenRequestStatusUserCancel:
		return "", ErrInteractionRequired
	case webTokenRequestStatusAccountProviderNotAvailable:
		return "", ErrNotAADJoined
	case webTokenRequestStatusProviderError:
		return "", fmt.Errorf("go-wam: WAM provider error (status %d)", status)
	case webTokenRequestStatusSuccess:
		// continue below
	default:
		return "", fmt.Errorf("go-wam: unexpected WAM status %d", status)
	}

	// get_ResponseData → IVectorView<IWebTokenResponse>
	// We take the first (and typically only) response.
	var responseVec unsafe.Pointer
	hr, _, _ = syscall.SyscallN(vtbl[vtblGetResponseData],
		uintptr(r.p),
		uintptr(unsafe.Pointer(&responseVec)),
	)
	if hr != 0 {
		return "", hresultError("IWebTokenRequestResult::get_ResponseData", hr)
	}
	defer comRelease(responseVec)

	vecVtbl := *(*[32]uintptr)(responseVec)
	var response unsafe.Pointer
	hr, _, _ = syscall.SyscallN(vecVtbl[vtblVectorViewGetAt],
		uintptr(responseVec),
		0, // index 0
		uintptr(unsafe.Pointer(&response)),
	)
	if hr != 0 {
		return "", hresultError("IVectorView::GetAt(0)", hr)
	}
	defer comRelease(response)

	// IWebTokenResponse::get_Token → HSTRING
	respVtbl := *(*[32]uintptr)(response)
	var tokenHStr hstring
	hr, _, _ = syscall.SyscallN(respVtbl[vtblGetToken],
		uintptr(response),
		uintptr(unsafe.Pointer(&tokenHStr)),
	)
	if hr != 0 {
		return "", hresultError("IWebTokenResponse::get_Token", hr)
	}
	defer tokenHStr.delete()

	tok := tokenHStr.String()
	if tok == "" {
		return "", fmt.Errorf("go-wam: WAM returned empty token")
	}
	return tok, nil
}
