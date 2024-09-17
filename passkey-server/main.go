package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/gorilla/mux"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
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

type User struct {
	gorm.Model
	Username   string `gorm:"uniqueIndex"`
	IsAdmin    bool
	Registered bool
	Passkeys   []Passkey
}

type Passkey struct {
	gorm.Model
	UserID       uint
	CredentialID []byte
	PublicKey    []byte
	SignCount    uint32
}

type Session struct {
	gorm.Model
	UserID        uint
	AccessToken   string `gorm:"uniqueIndex"`
	RefreshToken  string `gorm:"uniqueIndex"`
	ExpiresAt     time.Time
	RefreshExpiry time.Time
}

type OTP struct {
	gorm.Model
	Code      string `gorm:"uniqueIndex"`
	UserID    uint
	IsUsed    bool
	ExpiresAt time.Time
}

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
	return db.AutoMigrate(&User{}, &Passkey{}, &Session{}, &OTP{})
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

	r.HandleFunc("/admin/register", AdminRegisterHandler).Methods("POST")
	r.HandleFunc("/admin/create_user", AdminCreateUserHandler).Methods("POST")
	r.HandleFunc("/user/register", UserRegisterHandler).Methods("POST")
	r.HandleFunc("/user/begin_registration", BeginRegistrationHandler).Methods("POST")
	r.HandleFunc("/user/finish_registration", FinishRegistrationHandler).Methods("POST")
	r.HandleFunc("/user/begin_login", BeginLoginHandler).Methods("POST")
	r.HandleFunc("/user/finish_login", FinishLoginHandler).Methods("POST")

	log.Printf("Server is running on %s:%s", config.Host, config.Port)
	log.Fatal(http.ListenAndServe(config.Host+":"+config.Port, r))
}

func AdminRegisterHandler(w http.ResponseWriter, r *http.Request) {
	var request struct {
		OTP      string `json:"otp"`
		Username string `json:"username"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	if config.AdminOTP == "" || request.OTP != config.AdminOTP || request.Username != config.AdminUsername {
		http.Error(w, "Invalid OTP or username", http.StatusForbidden)
		return
	}

	adminUser := User{
		Username:   config.AdminUsername,
		IsAdmin:    true,
		Registered: false,
	}
	if err := db.Create(&adminUser).Error; err != nil {
		http.Error(w, "Error creating admin user", http.StatusInternalServerError)
		return
	}

	config.AdminOTP = ""

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Admin user created. Proceed with passkey registration.",
		"userId":  adminUser.ID,
	})
}

func AdminCreateUserHandler(w http.ResponseWriter, r *http.Request) {
	// TODO: Implement proper admin authentication

	var request struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	user := User{
		Username:   request.Username,
		IsAdmin:    false,
		Registered: false,
	}
	if err := db.Create(&user).Error; err != nil {
		http.Error(w, "Error creating user", http.StatusInternalServerError)
		return
	}

	otpCode := generateOTP()
	otp := OTP{
		Code:      otpCode,
		UserID:    user.ID,
		IsUsed:    false,
		ExpiresAt: time.Now().Add(15 * time.Minute),
	}
	if err := db.Create(&otp).Error; err != nil {
		http.Error(w, "Error generating OTP", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "User created successfully",
		"otp":     otpCode,
	})
}

func UserRegisterHandler(w http.ResponseWriter, r *http.Request) {
	var request struct {
		OTP string `json:"otp"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	var otp OTP
	if err := db.Where("code = ? AND is_used = ? AND expires_at > ?", request.OTP, false, time.Now()).First(&otp).Error; err != nil {
		http.Error(w, "Invalid or expired OTP", http.StatusForbidden)
		return
	}

	var user User
	if err := db.First(&user, otp.UserID).Error; err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	otp.IsUsed = true
	if err := db.Save(&otp).Error; err != nil {
		http.Error(w, "Error updating OTP", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "OTP verified. Proceed with passkey registration.",
		"userId":  user.ID,
	})
}

func BeginRegistrationHandler(w http.ResponseWriter, r *http.Request) {
	var request struct {
		UserID uint `json:"userId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	var user User
	if err := db.First(&user, request.UserID).Error; err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	options, _, err := webAuthn.BeginRegistration(&user)
	if err != nil {
		http.Error(w, "Error beginning registration", http.StatusInternalServerError)
		return
	}

	// Store sessionData securely (e.g., in a database or secure session store)
	// For simplicity, we'll store it in the user's session (not recommended for production)
	user.Passkeys = append(user.Passkeys, Passkey{
		UserID: user.ID,
		// Store sessionData here (you might want to encrypt it)
	})
	if err := db.Save(&user).Error; err != nil {
		http.Error(w, "Error saving session data", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(options)
}

func FinishRegistrationHandler(w http.ResponseWriter, r *http.Request) {
	var request struct {
		UserID uint `json:"userId"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	var user User
	if err := db.Preload("Passkeys").First(&user, request.UserID).Error; err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Retrieve sessionData from user's passkey (in production, use a secure session store)
	if len(user.Passkeys) == 0 {
		http.Error(w, "No session data found", http.StatusBadRequest)
		return
	}
	sessionData := webauthn.SessionData{} // Populate this from the stored data

	credential, err := webAuthn.FinishRegistration(&user, sessionData, r)
	if err != nil {
		http.Error(w, "Error finishing registration", http.StatusInternalServerError)
		return
	}

	// Store the new credential
	newPasskey := Passkey{
		UserID:       user.ID,
		CredentialID: credential.ID,
		PublicKey:    credential.PublicKey,
		SignCount:    credential.Authenticator.SignCount,
	}
	if err := db.Create(&newPasskey).Error; err != nil {
		http.Error(w, "Error saving credential", http.StatusInternalServerError)
		return
	}

	user.Registered = true
	if err := db.Save(&user).Error; err != nil {
		http.Error(w, "Error updating user", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message": "Registration successful",
	})
}

func BeginLoginHandler(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	var user User
	if err := db.Where("username = ?", request.Username).First(&user).Error; err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	options, _, err := webAuthn.BeginLogin(&user)
	if err != nil {
		http.Error(w, "Error beginning login", http.StatusInternalServerError)
		return
	}

	// Store sessionData securely (e.g., in a database or secure session store)
	// For simplicity, we'll store it in the user's session (not recommended for production)
	user.Passkeys = append(user.Passkeys, Passkey{
		UserID: user.ID,
		// Store sessionData here (you might want to encrypt it)
	})
	if err := db.Save(&user).Error; err != nil {
		http.Error(w, "Error saving session data", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(options)
}

func FinishLoginHandler(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Username string `json:"username"`
	}
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	var user User
	if err := db.Where("username = ?", request.Username).Preload("Passkeys").First(&user).Error; err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Retrieve sessionData from user's passkey (in production, use a secure session store)
	if len(user.Passkeys) == 0 {
		http.Error(w, "No session data found", http.StatusBadRequest)
		return
	}
	sessionData := webauthn.SessionData{} // Populate this from the stored data

	credential, err := webAuthn.FinishLogin(&user, sessionData, r)
	if err != nil {
		http.Error(w, "Error finishing login", http.StatusInternalServerError)
		return
	}

	// Update the credential's sign count
	var passkey Passkey
	if err := db.Where("credential_id = ?", credential.ID).First(&passkey).Error; err != nil {
		http.Error(w, "Error retrieving passkey", http.StatusInternalServerError)
		return
	}
	passkey.SignCount = credential.Authenticator.SignCount
	if err := db.Save(&passkey).Error; err != nil {
		http.Error(w, "Error updating passkey", http.StatusInternalServerError)
		return
	}

	// Generate and store session tokens
	accessToken := generateToken()
	refreshToken := generateToken()
	session := Session{
		UserID:        user.ID,
		AccessToken:   accessToken,
		RefreshToken:  refreshToken,
		ExpiresAt:     time.Now().Add(15 * time.Minute),
		RefreshExpiry: time.Now().Add(7 * 24 * time.Hour),
	}
	if err := db.Create(&session).Error; err != nil {
		http.Error(w, "Error creating session", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"message":      "Login successful",
		"accessToken":  accessToken,
		"refreshToken": refreshToken,
	})
}

func generateOTP() string {
	// TODO: Implement a secure OTP generation method
	return "123456"
}

func generateToken() string {
	// TODO: Implement a secure token generation method
	return "secure_token"
}

// Implement the webauthn.User interface for the User struct
func (u *User) WebAuthnID() []byte {
	return []byte(u.Username)
}

func (u *User) WebAuthnName() string {
	return u.Username
}

func (u *User) WebAuthnDisplayName() string {
	return u.Username
}

func (u *User) WebAuthnIcon() string {
	return ""
}

func (u *User) WebAuthnCredentials() []webauthn.Credential {
	var credentials []webauthn.Credential
	for _, passkey := range u.Passkeys {
		credentials = append(credentials, webauthn.Credential{
			ID:              passkey.CredentialID,
			PublicKey:       passkey.PublicKey,
			AttestationType: "", // Set this if you're using attestation
			Authenticator: webauthn.Authenticator{
				AAGUID:       []byte{},
				SignCount:    passkey.SignCount,
				CloneWarning: false,
			},
		})
	}
	return credentials
}
