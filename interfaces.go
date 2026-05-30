//go:build windows

package wam

// This file defines the COM/WinRT vtable layouts for the interfaces we call.
// Each struct mirrors the in-memory vtable pointer array for that interface.
//
// WinRT interface inheritance:
//   IUnknown         [0] QueryInterface  [1] AddRef  [2] Release
//   └─ IInspectable  [3] GetIids  [4] GetRuntimeClassName  [5] GetTrustLevel
//      └─ IFoo       [6..n] interface-specific methods
//
// GUIDs are taken from the Windows SDK headers (windows.security.authentication
// .web.core namespace). They are stable across Windows versions.

import (
	"golang.org/x/sys/windows"
)

// ── IIDs ─────────────────────────────────────────────────────────────────────

var (
	// IWebAuthenticationCoreManagerStatics
	iidWebAuthCoreManagerStatics = &windows.GUID{
		Data1: 0x6aca7c92,
		Data2: 0xa581,
		Data3: 0x4479,
		Data4: [8]byte{0x9c, 0x10, 0x75, 0x2e, 0xff, 0x44, 0xfd, 0x34},
	}

	// IWebAccountProvider
	iidWebAccountProvider = &windows.GUID{
		Data1: 0x29dd0420,
		Data2: 0xb7eb,
		Data3: 0x41db,
		Data4: [8]byte{0x92, 0x1c, 0x7f, 0x83, 0xde, 0xfa, 0x7d, 0x23},
	}

	// IWebTokenRequestFactory
	iidWebTokenRequestFactory = &windows.GUID{
		Data1: 0x6cf2141c,
		Data2: 0x0ff0,
		Data3: 0x4c67,
		Data4: [8]byte{0xb8, 0x4f, 0x99, 0xdd, 0xbe, 0x4a, 0x72, 0xc9},
	}

	// IWebTokenRequest
	iidWebTokenRequest = &windows.GUID{
		Data1: 0xb77b4d68,
		Data2: 0xadcb,
		Data3: 0x4673,
		Data4: [8]byte{0xb3, 0x64, 0x0c, 0xf7, 0xb3, 0x5c, 0xaf, 0x97},
	}

	// IWebTokenRequestResult
	iidWebTokenRequestResult = &windows.GUID{
		Data1: 0xc12a8305,
		Data2: 0xd1f8,
		Data3: 0x4483,
		Data4: [8]byte{0x8d, 0x54, 0x38, 0xee, 0x1a, 0x2e, 0xb5, 0xa5},
	}

	// IWebTokenResponse
	iidWebTokenResponse = &windows.GUID{
		Data1: 0x67a7c5ca,
		Data2: 0x83f6,
		Data3: 0x44c6,
		Data4: [8]byte{0xa3, 0xb1, 0x0e, 0xb6, 0x9e, 0x41, 0xfa, 0x8a},
	}

	// IWebAccount
	iidWebAccount = &windows.GUID{
		Data1: 0x69473eb2,
		Data2: 0x8031,
		Data3: 0x49be,
		Data4: [8]byte{0x80, 0xbb, 0x96, 0xcb, 0x46, 0xd9, 0x9a, 0xba},
	}

	// IFindAllAccountsResult — discovered via PowerShell GetInterfaces
	iidFindAllAccountsResult = &windows.GUID{
		Data1: 0xa5812b5d,
		Data2: 0xb72e,
		Data3: 0x420c,
		Data4: [8]byte{0x86, 0xab, 0xaa, 0xc0, 0xd7, 0xb7, 0x26, 0x1f},
	}
)

// ── vtable index constants ────────────────────────────────────────────────────
//
// WinRT vtables start with IUnknown (3 slots) + IInspectable (3 slots) = 6
// slots before any interface-specific methods.

const iinspectableBase = 6

// IWebAuthenticationCoreManagerStatics method indices (after IInspectable base)
const (
	// FindAccountProviderAsync(providerId HSTRING) → IAsyncOperation<IWebAccountProvider>
	vtblFindAccountProvider = iinspectableBase + 0
	// FindAccountProviderAsync(providerId, authority HSTRING) → IAsyncOperation<IWebAccountProvider>
	vtblFindAccountProviderWithAuthority = iinspectableBase + 1
	// GetTokenSilentlyAsync(request) → IAsyncOperation<IWebTokenRequestResult>
	vtblGetTokenSilently = iinspectableBase + 2
	// GetTokenSilentlyAsync(request, account) → IAsyncOperation<IWebTokenRequestResult>
	vtblGetTokenSilentlyWithAccount = iinspectableBase + 3
	// RequestTokenAsync(request) → IAsyncOperation<IWebTokenRequestResult>
	vtblRequestToken = iinspectableBase + 4
	// RequestTokenAsync(request, account) → IAsyncOperation<IWebTokenRequestResult>
	vtblRequestTokenWithAccount = iinspectableBase + 5
	// FindAllAccountsAsync(provider) → IAsyncOperation<FindAllAccountsResult>
	vtblFindAllAccounts = iinspectableBase + 6
)

// IWebTokenRequestFactory method indices
const (
	// CreateWithProviderAndScope(provider, scope, clientId, promptType) → IWebTokenRequest
	vtblCreateWebTokenRequest = iinspectableBase + 0
)

// IWebTokenRequestResult method indices
const (
	// get_ResponseData → IVectorView<IWebTokenResponse>
	vtblGetResponseData = iinspectableBase + 0
	// get_ResponseStatus → WebTokenRequestStatus enum
	vtblGetResponseStatus = iinspectableBase + 1
	// get_ResponseError → WebProviderError
	vtblGetResponseError = iinspectableBase + 2
)

// IWebTokenResponse method indices
const (
	// get_Token → HSTRING
	vtblGetToken = iinspectableBase + 0
	// get_WebAccount → IWebAccount
	vtblGetWebAccount = iinspectableBase + 1
	// get_Properties → IMap<HSTRING, HSTRING>
	vtblGetProperties = iinspectableBase + 2
)

// IWebAccount method indices
const (
	// get_WebAccountProvider → IWebAccountProvider
	vtblGetWebAccountProvider = iinspectableBase + 0
	// get_Id → HSTRING
	vtblGetWebAccountId = iinspectableBase + 1
	// get_UserName → HSTRING
	vtblGetWebAccountUserName = iinspectableBase + 2
)

// IFindAllAccountsResult method indices (order from PowerShell GetInterfaces output)
const (
	// get_Accounts → IVectorView<IWebAccount>
	vtblFindAllResultGetAccounts = iinspectableBase + 0
	// get_Status → FindAllWebAccountsStatus enum
	vtblFindAllResultGetStatus = iinspectableBase + 1
	// get_ProviderError → IWebProviderError
	vtblFindAllResultGetProviderErr = iinspectableBase + 2
)

// FindAllWebAccountsStatus enum values
const (
	findAllWebAccountsSuccess    = uint32(0)
	findAllWebAccountsNotAllowed = uint32(1)
)

// IVectorView<T> method indices (shared across all typed vector views)
const (
	// get_Size → uint32
	vtblVectorViewSize = iinspectableBase + 0
	// GetAt(index uint32) → T
	vtblVectorViewGetAt = iinspectableBase + 1
)

// WebTokenRequestStatus enum values
const (
	webTokenRequestStatusSuccess              = 0
	webTokenRequestStatusUserCancel           = 1
	webTokenRequestStatusAccountSwitch        = 2
	webTokenRequestStatusUserInteractionRequired = 3
	webTokenRequestStatusAccountProviderNotAvailable = 4
	webTokenRequestStatusProviderError        = 5
)
