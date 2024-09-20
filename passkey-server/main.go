package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/gorilla/mux"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var db *gorm.DB
var config *Config
var webAuthn *webauthn.WebAuthn

func LoadConfig() *Config {
	return &Config{
		AdminUsername: os.Getenv("ADMIN_USERNAME"),
		AdminOTP:      os.Getenv("ADMIN_OTP"),
		DBFile:        os.Getenv("DB_FILE"),
		Port:          os.Getenv("PORT"),
		Host:          os.Getenv("HOST"),
		RPDisplayName: os.Getenv("RP_DISPLAY_NAME"),
		RPID:          os.Getenv("RP_ID"),
		RPOrigins:     os.Getenv("RP_ORIGINS"),
	}
}

func InitDB() error {
	var err error
	db, err = gorm.Open(sqlite.Open(config.DBFile), &gorm.Config{})
	if err != nil {
		return err
	}
	return db.AutoMigrate(&WebAuthnUser{}, &WebAuthnCredential{}, &WebAuthnSession{})
}

func BeginRegistration(w http.ResponseWriter, r *http.Request) {
	// get username from request
	username := r.URL.Query().Get("username")

	var user *WebAuthnUser

	err := db.Where(WebAuthnUser{Username: username}).First(&user).Error

	if err != nil || user == nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	options, session, err := webAuthn.BeginRegistration(user)
	if err != nil {
		http.Error(w, "Failed to begin registration", http.StatusInternalServerError)
		return
	}
	// delete prior session if it exists
	err = db.Where(WebAuthnSession{UserID: user.ID}).Delete(&WebAuthnSession{}).Error
	if err != nil {
		http.Error(w, "Failed to delete prior session", http.StatusInternalServerError)
		return
	}

	// store the session
	err = db.Create(&WebAuthnSession{
		Challenge:            session.Challenge,
		UserID:               session.UserID,
		Expires:              session.Expires,
		RelyingPartyID:       session.RelyingPartyID,
		AllowedCredentialIDs: session.AllowedCredentialIDs,
		UserVerification:     session.UserVerification,
		Extensions:           session.Extensions,
	}).Error

	if err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	// respond with the options
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(options)
}

func FinishRegistration(w http.ResponseWriter, r *http.Request) {
	// get username from request
	username := r.URL.Query().Get("username")

	var user *WebAuthnUser

	err := db.Where(WebAuthnUser{Username: username}).First(&user).Error
	if err != nil || user == nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// get session
	session := &WebAuthnSession{}
	err = db.Where(WebAuthnSession{UserID: user.ID}).First(&session).Error
	if err != nil || session == nil {
		http.Error(w, "Session not found", http.StatusNotFound)
		return
	}

	credential, err := webAuthn.FinishRegistration(user, webauthn.SessionData{
		Challenge:            session.Challenge,
		UserID:               session.UserID,
		Expires:              session.Expires,
		RelyingPartyID:       session.RelyingPartyID,
		AllowedCredentialIDs: session.AllowedCredentialIDs,
		UserVerification:     session.UserVerification,
		Extensions:           session.Extensions,
	}, r)
	if err != nil {
		http.Error(w, "Failed to finish registration", http.StatusInternalServerError)
		return
	}

	// store the credential
	err = db.Create(&WebAuthnCredential{
		UserID:                        user.ID,
		ID:                            credential.ID,
		PublicKey:                     credential.PublicKey,
		Transport:                     credential.Transport,
		FlagUserPresent:               credential.Flags.UserPresent,
		FlagUserVerified:              credential.Flags.UserVerified,
		FlagBackupEligible:            credential.Flags.BackupEligible,
		FlagBackupState:               credential.Flags.BackupState,
		AttestationType:               credential.AttestationType,
		AttestationClientDataJSON:     credential.Attestation.ClientDataJSON,
		AttestationClientDataHash:     credential.Attestation.ClientDataHash,
		AttestationAuthenticatorData:  credential.Attestation.AuthenticatorData,
		AttestationPublicKeyAlgorithm: credential.Attestation.PublicKeyAlgorithm,
		AttestationObject:             credential.Attestation.Object,
		AuthenticatorAAGUID:           credential.Authenticator.AAGUID,
		AuthenticatorSignCount:        credential.Authenticator.SignCount,
		AuthenticatorCloneWarning:     credential.Authenticator.CloneWarning,
		AuthenticatorAttachment:       credential.Authenticator.Attachment,
	}).Error

	if err != nil {
		http.Error(w, "Failed to store credential", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Registration successful"))
}

func BeginLogin(w http.ResponseWriter, r *http.Request) {
	// get username from request
	username := r.URL.Query().Get("username")

	var user *WebAuthnUser

	err := db.Where(WebAuthnUser{Username: username}).First(&user).Error
	if err != nil || user == nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	options, session, err := webAuthn.BeginLogin(user)
	if err != nil {
		http.Error(w, "Failed to begin login", http.StatusInternalServerError)
		return
	}

	//delete prior session if it exists
	err = db.Where(WebAuthnSession{UserID: user.ID}).Delete(&WebAuthnSession{}).Error
	if err != nil {
		http.Error(w, "Failed to delete prior session", http.StatusInternalServerError)
		return
	}

	// store the session
	err = db.Create(&WebAuthnSession{
		Challenge:            session.Challenge,
		UserID:               session.UserID,
		Expires:              session.Expires,
		RelyingPartyID:       session.RelyingPartyID,
		AllowedCredentialIDs: session.AllowedCredentialIDs,
		UserVerification:     session.UserVerification,
		Extensions:           session.Extensions,
	}).Error

	if err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	// respond with the options
	w.WriteHeader(http.StatusOK)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(options)
}

func FinishLogin(w http.ResponseWriter, r *http.Request) {
	// get username from request
	username := r.URL.Query().Get("username")

	var user *WebAuthnUser

	err := db.Where(WebAuthnUser{Username: username}).First(&user).Error
	if err != nil || user == nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// get session
	session := &WebAuthnSession{}
	err = db.Where(WebAuthnSession{UserID: user.ID}).First(&session).Error
	if err != nil || session == nil {
		http.Error(w, "Session not found", http.StatusNotFound)
		return
	}

	credential, err := webAuthn.FinishLogin(user, webauthn.SessionData{
		Challenge:            session.Challenge,
		UserID:               session.UserID,
		Expires:              session.Expires,
		RelyingPartyID:       session.RelyingPartyID,
		AllowedCredentialIDs: session.AllowedCredentialIDs,
		UserVerification:     session.UserVerification,
		Extensions:           session.Extensions,
	}, r)

	if err != nil {
		http.Error(w, "Failed to finish login", http.StatusInternalServerError)
		return
	}

	if credential.Authenticator.CloneWarning {
		http.Error(w, "Clone warning", http.StatusBadRequest)
		return
	}

	var existingCredential *WebAuthnCredential
	err = db.Where(WebAuthnCredential{ID: credential.ID}).First(&existingCredential).Error
	if err != nil || existingCredential == nil {
		http.Error(w, "Existing credential not found", http.StatusNotFound)
		return
	}
	// if authenticator uses counter, check if less than or equal to previous counter, detecting possible comprimised credential
	if existingCredential.AuthenticatorSignCount > 0 && credential.Authenticator.SignCount <= existingCredential.AuthenticatorSignCount {
		http.Error(w, "Invalid sign count", http.StatusBadRequest)
		return
	}

	// update credential
	err = db.Model(&WebAuthnCredential{ID: credential.ID}).Updates(WebAuthnCredential{
		AuthenticatorSignCount: credential.Authenticator.SignCount,
	}).Error
	if err != nil {
		http.Error(w, "Failed to update credential", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Login successful"))
}

func main() {
	config = LoadConfig()
	err := InitDB()
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	webAuthnConfig := &webauthn.Config{
		RPDisplayName: config.RPDisplayName,
		RPID:          config.RPID,
		RPOrigins:     strings.Split(config.RPOrigins, ","),
	}

	webAuthn, err = webauthn.New(webAuthnConfig)
	if err != nil {
		log.Fatalf("Failed to initialize WebAuthn: %v", err)
	}

	r := mux.NewRouter()

	r.HandleFunc("/register/begin", BeginRegistration).Methods("POST")
	r.HandleFunc("/register/finish", FinishRegistration).Methods("POST")
	r.HandleFunc("/login/begin", BeginLogin).Methods("POST")
	r.HandleFunc("/login/finish", FinishLogin).Methods("POST")

	log.Printf("Server is running on %s:%s", config.Host, config.Port)
	log.Fatal(http.ListenAndServe(config.Host+":"+config.Port, r))
}
