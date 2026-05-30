# go-wam

Pure-Go client for the Windows Web Account Manager (WAM) broker. Acquires
Azure AD ID tokens silently — no UI, no CGo, no MSAL dependency.

WAM is the same SSO layer Windows uses internally for "Sign in with Microsoft".
When a device is Azure AD joined and the user has a cached credential, a signed
RS256 JWT is returned in under a second with no user interaction.

## Requirements

- Windows 10 1803+ / Windows Server 2019+ (WAM available since RS4)
- Device must be Azure AD joined or Hybrid AD joined
- An interactive user session (not SYSTEM)
- An Azure AD app registration with the calling app's client ID

## Usage

```go
import wam "github.com/Allod-Solutions/go-wam"

tok, err := wam.GetTokenSilently(ctx, tenantID, clientID)
switch {
case errors.Is(err, wam.ErrNotAADJoined):
    // device is not enrolled — skip silently
case errors.Is(err, wam.ErrNoAccount):
    // no cached WAM account for this tenant
case errors.Is(err, wam.ErrInteractionRequired):
    // silent auth failed — user must sign in interactively first
case err != nil:
    log.Fatal(err)
default:
    // tok is a signed RS256 JWT; verify server-side via the tenant JWKS endpoint:
    // https://login.microsoftonline.com/{tenantID}/v2.0/.well-known/openid-configuration
}
```

### List cached accounts

```go
accounts, err := wam.FindAccounts(ctx, tenantID)
for _, a := range accounts {
    fmt.Println(a.UserName) // e.g. "niklas@company.com"
}
```

## How it works

WAM is a WinRT component exposed through the
`Windows.Security.Authentication.Web.Core` namespace. This library calls the
COM/WinRT vtables directly via `syscall.SyscallN` — no generated bindings, no
CGo, no runtime dependency beyond `golang.org/x/sys/windows`.

The call sequence:

1. `RoGetActivationFactory` → `IWebAuthenticationCoreManagerStatics`
2. `FindAccountProviderAsync` with the Microsoft AAD provider ID and tenant authority
3. `FindAllAccountsAsync` → `IFindAllAccountsResult` → `IVectorView<IWebAccount>`
4. `WebTokenRequest` constructed with provider, client ID, and `openid email profile` scope
5. `GetTokenSilentlyAsync` with the cached account → `IWebTokenRequestResult`
6. `IWebTokenResponse::get_Token` → signed JWT

Async operations are polled at 5 ms intervals rather than using completion
callbacks, avoiding COM apartment threading complexity from Go goroutines.

## Server-side verification

The returned token is a standard Azure AD ID token. Verify it using the
tenant's JWKS endpoint:

```
GET https://login.microsoftonline.com/{tenantID}/v2.0/.well-known/openid-configuration
```

## Testing

Unit tests use a mock backend (`internal/testbackend`) and run on any Windows
machine without AAD join or network access:

```
go test ./...
```

Integration tests require an AAD-joined machine with `WAM_TEST_TENANT_ID` and
`WAM_TEST_CLIENT_ID` set:

```
go test -tags wam_integration -v ./...
```

## Non-goals

- Interactive sign-in flows (device code, browser redirect)
- Non-Windows platforms
- Access tokens (only ID tokens are returned)

## License

MIT
