# WebAuthn Library

This library is meant to handle [Web Authentication](https://www.w3.org/TR/webauthn) for Go apps that wish to implement 
a passwordless solution for users. This library conforms as much as possible to the guidelines and implementation
procedures outlined by the document.

## Quickstart

`go get github.com/go-webauthn/webauthn` and initialize it in your application with basic configuration values. 

Make sure your `user` model is able to handle the interface functions laid out in `webauthn/types.go`. This means also 
supporting the storage and retrieval of the credential and authenticator structs in `webauthn/credential.go` and 
`webauthn/authenticator.go`, respectively.


```go
// User is an interface with the Relying Party's User entry and provides the fields and methods needed for WebAuthn
// registration operations.
type User interface {
	// WebAuthnID provides the user handle of the user account. A user handle is an opaque byte sequence with a maximum
	// size of 64 bytes, and is not meant to be displayed to the user.
	//
	// To ensure secure operation, authentication and authorization decisions MUST be made on the basis of this id
	// member, not the displayName nor name members. See Section 6.1 of [RFC8266].
	//
	// It's recommended this value is completely random and uses the entire 64 bytes.
	//
	// Specification: §5.4.3. User Account Parameters for Credential Generation (https://w3c.github.io/webauthn/#dom-publickeycredentialuserentity-id)
	WebAuthnID() []byte

	// WebAuthnName provides the name attribute of the user account during registration and is a human-palatable name for the user
	// account, intended only for display. For example, "Alex Müller" or "田中倫". The Relying Party SHOULD let the user
	// choose this, and SHOULD NOT restrict the choice more than necessary.
	//
	// Specification: §5.4.3. User Account Parameters for Credential Generation (https://w3c.github.io/webauthn/#dictdef-publickeycredentialuserentity)
	WebAuthnName() string

	// WebAuthnDisplayName provides the name attribute of the user account during registration and is a human-palatable
	// name for the user account, intended only for display. For example, "Alex Müller" or "田中倫". The Relying Party
	// SHOULD let the user choose this, and SHOULD NOT restrict the choice more than necessary.
	//
	// Specification: §5.4.3. User Account Parameters for Credential Generation (https://www.w3.org/TR/webauthn/#dom-publickeycredentialuserentity-displayname)
	WebAuthnDisplayName() string

	// WebAuthnCredentials provides the list of Credential objects owned by the user.
	WebAuthnCredentials() []Credential
}

// SessionData is the data that should be stored by the Relying Party for the duration of the web authentication
// ceremony.
type SessionData struct {
	Challenge            string    `json:"challenge"`
	RelyingPartyID       string    `json:"rpId"`
	UserID               []byte    `json:"user_id"`
	AllowedCredentialIDs [][]byte  `json:"allowed_credentials,omitempty"`
	Expires              time.Time `json:"expires"`

	UserVerification protocol.UserVerificationRequirement `json:"userVerification"`
	Extensions       protocol.AuthenticationExtensions    `json:"extensions,omitempty"`
}
```

## Examples

The following examples show some basic use cases of the library. For consistency sake the following variables are used
to denote specific things:

- Variable `webAuthn`: the `webauthn.WebAuthn` instance you initialize elsewhere in your code
- Variable `datastore`: the pseudocode backend service that stores your webauthn session data and users such as PostgreSQL 
- Variable `session`: the webauthn.SessionData object
- Variable `user`: your webauthn.User implementation

We try to avoid using specific external libraries (excluding stdlib) where possible, and you'll need to adapt these
examples with this in mind.

### Initialize the request handler

```go
package example

import (
	"fmt"

	"github.com/go-webauthn/webauthn/webauthn"
)

var (
	webAuthn *webauthn.WebAuthn
	err error
)

// Your initialization function
func main() {
	wconfig := &webauthn.Config{
		RPDisplayName: "Go Webauthn", // Display Name for your site
		RPID: "go-webauthn.local", // Generally the FQDN for your site
		RPOrigins: []string{"https://login.go-webauthn.local"}, // The origin URLs allowed for WebAuthn requests
	}
	
	if webAuthn, err = webauthn.New(wconfig); err != nil {
		fmt.Println(err)
	}
}
```

### Registering an account

```go
package example

func BeginRegistration(w http.ResponseWriter, r *http.Request) {
	user := datastore.GetUser() // Find or create the new user  
	options, session, err := webAuthn.BeginRegistration(user)
	// handle errors if present
	// store the sessionData values 
	JSONResponse(w, options, http.StatusOK) // return the options generated
	// options.publicKey contain our registration options
}

func FinishRegistration(w http.ResponseWriter, r *http.Request) {
	user := datastore.GetUser() // Get the user
	
	// Get the session data stored from the function above
	session := datastore.GetSession()
		
	credential, err := webAuthn.FinishRegistration(user, session, r)
	if err != nil {
		// Handle Error and return.

		return
	}
	
	// If creation was successful, store the credential object
	// Pseudocode to add the user credential.
	user.AddCredential(credential)
	datastore.SaveUser(user)

	JSONResponse(w, "Registration Success", http.StatusOK) // Handle next steps
}
```

### Logging into an account

```go
package example

func BeginLogin(w http.ResponseWriter, r *http.Request) {
	user := datastore.GetUser() // Find the user
	
	options, session, err := webAuthn.BeginLogin(user)
	if err != nil {
		// Handle Error and return.

		return
	}
	
	// store the session values
	datastore.SaveSession(session)
	
	JSONResponse(w, options, http.StatusOK) // return the options generated
	// options.publicKey contain our registration options
}

func FinishLogin(w http.ResponseWriter, r *http.Request) {
	user := datastore.GetUser() // Get the user 
	
	// Get the session data stored from the function above
	session := datastore.GetSession()
	
	credential, err := webAuthn.FinishLogin(user, session, r)
	if err != nil {
		// Handle Error and return.

		return
	}

	// Handle credential.Authenticator.CloneWarning

	// If login was successful, update the credential object
	// Pseudocode to update the user credential.
	user.UpdateCredential(credential)
	datastore.SaveUser(user)
	
	JSONResponse(w, "Login Success", http.StatusOK)
}
```

## Modifying Credential Options

You can modify the default credential creation options for registration and login by providing optional structs to the 
`BeginRegistration` and `BeginLogin` functions. 

### Registration modifiers

You can modify the registration options in the following ways:

```go
package example

import (
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

var webAuthn webauthn.WebAuthn // init this in your init function

func beginRegistration() {
	// Updating the AuthenticatorSelection options. 
	// See the struct declarations for values
	authSelect := protocol.AuthenticatorSelection{
		AuthenticatorAttachment: protocol.AuthenticatorAttachment("platform"),
		RequireResidentKey: protocol.ResidentKeyNotRequired(),
		UserVerification: protocol.VerificationRequired,
	}

	// Updating the ConveyencePreference options. 
	// See the struct declarations for values
	conveyancePref := protocol.PreferNoAttestation

	user := datastore.GetUser() // Get the user  
	opts, session, err := webAuthn.BeginRegistration(user, webauthn.WithAuthenticatorSelection(authSelect), webauthn.WithConveyancePreference(conveyancePref))

	// Handle next steps
}
```

### Login modifiers

You can modify the login options to allow only certain credentials:

```go
package example

import (
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

var webAuthn webauthn.WebAuthn // init this in your init function

func beginLogin() {
	// Updating the AuthenticatorSelection options. 
	// See the struct declarations for values
	allowList := make([]protocol.CredentialDescriptor, 1)
	allowList[0] = protocol.CredentialDescriptor{
		CredentialID: credentialToAllowID,
		Type: protocol.CredentialType("public-key"),
	}

	user := datastore.GetUser() // Get the user  

	opts, session, err := w.BeginLogin(user, webauthn.WithAllowedCredentials(allowList))

	// Handle next steps
}
```

## Timeout Mechanics

The library by default does not enforce timeouts. However the default timeouts sent to the browser are taken from the
specification. You can override both of these behaviours however.

```go
package example

import (
	"fmt"
	"time"
	
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

func main() {
	wconfig := &webauthn.Config{
		RPDisplayName: "Go Webauthn",                               // Display Name for your site
		RPID:          "go-webauthn.local",                         // Generally the FQDN for your site
		RPOrigins:     []string{"https://login.go-webauthn.local"}, // The origin URLs allowed for WebAuthn requests
		Timeouts: webauthn.TimeoutsConfig{
			Login: webauthn.TimeoutConfig{
				Enforce:    true, // Require the response from the client comes before the end of the timeout.
				Timeout:    time.Second * 60, // Standard timeout for login sessions.
				TimeoutUVD: time.Second * 60, // Timeout for login sessions which have user verification set to discouraged.
			},
			Registration: webauthn.TimeoutConfig{
				Enforce:    true, // Require the response from the client comes before the end of the timeout.
				Timeout:    time.Second * 60, // Standard timeout for registration sessions.
				TimeoutUVD: time.Second * 60, // Timeout for login sessions which have user verification set to discouraged.
			},
		},
	}
	
	webAuthn, err := webauthn.New(wconfig)
	if err != nil {
		fmt.Println(err)
	}
}
```

## Credential Record

The WebAuthn Level 3 specification describes the Credential Record which includes several required and optional elements
that you should store for. See [§ 4 Terminology](https://www.w3.org/TR/webauthn-3/#credential-record) for details.

This section describes this element. 

The fields listed in the specification have corresponding fields in the [webauthn.Credential] struct. See the below
table for more information. We also include JSON mappings for those that wish to just store these values as JSON.

|    Specification Field    |       Library Field        |         JSON Field         |                                           Notes                                           |
|:-------------------------:|:--------------------------:|:--------------------------:|:-----------------------------------------------------------------------------------------:|
|           type            |            N/A             |            N/A             |                       This field is always `publicKey` for WebAuthn                       |
|            id             |             ID             |             id             |                                                                                           |
|         publicKey         |         PublicKey          |         publicKey          |                                                                                           |
|         signCount         |  Authenticator.SignCount   |  authenticator.signCount   |                                                                                           |
|        transports         |         Transport          |         transport          |                                                                                           |
|       uvInitialized       |     Flags.UserVerified     |     flags.userVerified     |                                                                                           |
|      backupEligible       |    Flags.BackupEligible    |    flags.backupEligible    |                                                                                           |
|        backupState        |     Flags.BackupState      |     flags.backupState      |                                                                                           |
|     attestationObject     |     Attestation.Object     |     attestation.object     | This field is a composite of the attestationObject and the relevant values to validate it |
| attestationClientDataJSON | Attestation.ClientDataJSON | attestation.clientDataJSON |                                                                                           |

### Storage

It is also important to note that restoring the [webauthn.Credential] with the correct values will likely affect the
validity of the [webauthn.Credential], i.e. if some values are not restored the [webauthn.Credential] may fail
validation in this scenario.

### Verification

As long as the [webauthn.Credential] struct has exactly the same values when restored the [Credential Verify] function 
can be leveraged to verify the credential against the [metadata.Provider]. This can be either done during registration,
on every login, or with a audit schedule.

In addition to using the [Credential Verify] function the 
[webauthn.Config](https://pkg.go.dev/github.com/go-webauthn/webauthn/webauthn#Config) can contain a provider which will
process all registrations automatically.

At this time no tooling exists to verify the credential automatically outside the registration flow. Implementation of
this is considered domain logic and beyond the scope of what we provide documentation for; we just provide the necessary
tooling to implement this yourself.

## Acknowledgements

We graciously acknowledge the original authors of this library [github.com/duo-labs/webauthn] for their amazing
implementation. Without their amazing work this library could not exist.


[github.com/duo-labs/webauthn]: https://github.com/duo-labs/webauthn
[webauthn.Credential]: https://pkg.go.dev/github.com/go-webauthn/webauthn/webauthn#Credential
[metadata.Provider]: https://pkg.go.dev/github.com/go-webauthn/webauthn/metadata#Provider
[Credential Verify]: https://pkg.go.dev/github.com/go-webauthn/webauthn/webauthn#Credential.Verify