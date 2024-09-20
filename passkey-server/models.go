package main

import (
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

type Config struct {
	AdminOTP      string
	AdminUsername string
	DBFile        string
	Port          string
	Host          string
	RPDisplayName string
	RPID          string
	RPOrigins     string
}

// WebAuthnUser represents the user model for WebAuthn operations
type WebAuthnUser struct {
	ID          []byte `gorm:"type:blob;uniqueIndex"`
	Username    string
	DisplayName string
	Credentials []WebAuthnCredential `gorm:"foreignKey:UserID"`
}

// WebAuthnCredential represents the credential model for WebAuthn
type WebAuthnCredential struct {
	UserID                        []byte `gorm:"type:blob"`
	ID                            []byte `gorm:"type:blob;uniqueIndex"`
	PublicKey                     []byte `gorm:"type:blob"`
	AttestationType               string
	Transport                     []protocol.AuthenticatorTransport
	FlagUserPresent               bool
	FlagUserVerified              bool
	FlagBackupEligible            bool
	FlagBackupState               bool
	AuthenticatorAAGUID           []byte `gorm:"type:blob"`
	AuthenticatorSignCount        uint32
	AuthenticatorCloneWarning     bool
	AuthenticatorAttachment       protocol.AuthenticatorAttachment
	AttestationClientDataJSON     []byte `gorm:"type:blob"`
	AttestationClientDataHash     []byte `gorm:"type:blob"`
	AttestationAuthenticatorData  []byte `gorm:"type:blob"`
	AttestationPublicKeyAlgorithm int64  `gorm:"type:bigint"`
	AttestationObject             []byte `gorm:"type:blob"`
}

// WebAuthnSession represents the session data for WebAuthn ceremonies
type WebAuthnSession struct {
	Challenge            string
	RelyingPartyID       string
	UserID               []byte   `gorm:"type:blob;uniqueIndex"`
	AllowedCredentialIDs [][]byte `gorm:"type:blob"`
	Expires              time.Time
	UserVerification     protocol.UserVerificationRequirement
	Extensions           protocol.AuthenticationExtensions `gorm:"type:blob"`
}

// WebAuthnID implements the webauthn.User interface
func (u *WebAuthnUser) WebAuthnID() []byte {
	return u.ID
}

// WebAuthnName implements the webauthn.User interface
func (u *WebAuthnUser) WebAuthnName() string {
	return u.Username
}

// WebAuthnDisplayName implements the webauthn.User interface
func (u *WebAuthnUser) WebAuthnDisplayName() string {
	return u.DisplayName
}

// WebAuthnCredentials implements the webauthn.User interface
func (u *WebAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	var credentials []webauthn.Credential
	for _, cred := range u.Credentials {
		credentials = append(credentials, webauthn.Credential{
			ID:              cred.ID,
			PublicKey:       cred.PublicKey,
			AttestationType: cred.AttestationType,
			Transport:       cred.Transport,
			Flags: webauthn.CredentialFlags{
				UserPresent:    cred.FlagUserPresent,
				UserVerified:   cred.FlagUserVerified,
				BackupEligible: cred.FlagBackupEligible,
				BackupState:    cred.FlagBackupState,
			},
			Authenticator: webauthn.Authenticator{
				AAGUID:       cred.AuthenticatorAAGUID,
				SignCount:    cred.AuthenticatorSignCount,
				CloneWarning: cred.AuthenticatorCloneWarning,
				Attachment:   cred.AuthenticatorAttachment,
			},
			Attestation: webauthn.CredentialAttestation{
				ClientDataJSON:     cred.AttestationClientDataJSON,
				ClientDataHash:     cred.AttestationClientDataHash,
				AuthenticatorData:  cred.AttestationAuthenticatorData,
				PublicKeyAlgorithm: cred.AttestationPublicKeyAlgorithm,
				Object:             cred.AttestationObject,
			},
		})
	}
	return credentials
}
