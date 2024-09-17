## Project Overview

- **Language:** Go (Golang)
- **Server Name:** passkey-server
- **Authentication Method:** PassKeys only (based on FIDO2/WebAuthn standards)
- **Bootstrap Mechanism:** One-time password (OTP) via environment variable for the root admin
- **Database:** SQLite for storing user credentials and related data
- **No Sign-ups:** Users are pre-provisioned; no self-service registration
