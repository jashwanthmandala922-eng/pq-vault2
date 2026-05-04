# PQ Vault - Post-Quantum Password Manager

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Android%20%7C%20Windows-blue" alt="Platform">
  <img src="https://img.shields.io/badge/License-MIT-green" alt="License">
  <img src="https://img.shields.io/badge/Security-Post--Quantum-orange" alt="Security">
</p>

## 🔐 About

PQ Vault is a **post-quantum password manager** that uses cutting-edge cryptographic algorithms to protect your credentials against both classical and quantum computer attacks.

### Key Features

- **Post-Quantum Encryption** - ML-KEM-768 + ML-DSA-65
- **OAuth-Only Login** - Google/Apple Sign-In
- **Local Vault Storage** - Your data never leaves your device
- **P2P Sync** - Local network sync with ChaCha20-Poly1305
- **TOTP Authenticator** - Built-in 2FA codes
- **Passkeys** - Hybrid ECDSA + PQC WebAuthn
- **Password Generator** - Characters and passphrases
- **Autofiller** - Android Autofill Service

## 🏗️ Architecture

```
hiiiii/
├── securevault-core/     # Rust cryptographic library
│   └── src/
│       ├── crypto/      # ML-KEM, ML-DSA, AES, ChaCha20
│       ├── vault/       # Encrypted vault storage
│       ├── sync/        # P2P synchronization
│       ├── behavior/   # Keystroke analysis
│       ├── passkey/    # WebAuthn implementation
│       ├── totp/       # TOTP generator
│       └── generator/  # Password generation
│
├── android/             # Android app (Kotlin)
│   └── app/src/main/
│       └── java/com/pqvault/app/
│           ├── data/    # Repository, Native bindings
│           ├── di/     # Hilt dependency injection
│           ├── service/ # Autofill service
│           └── ui/    # Jetpack Compose screens
│
├── windows/            # Windows app (Tauri/React)
│   ├── src/           # React frontend
│   └── src-tauri/    # Rust backend
│
└── .github/workflows/ # CI/CD pipelines
```

## 🔒 Security

### Post-Quantum Algorithms

| Algorithm | Type | Security Level |
|-----------|------|----------------|
| ML-KEM-768 | KEM | 128-bit |
| ML-DSA-65 | Signature | 192-bit |
| AES-256-GCM | Symmetric | 256-bit |
| ChaCha20-Poly1305 | AEAD | 256-bit |

### Key Derivation

- OAuth token → HKDF → Master Key
- Master Key + Salt → Session Key (Argon2id)
- Session Key → Vault Encryption

## 🚀 Getting Started

### Prerequisites

- Android SDK 34+
- Rust 1.75+
- Node.js 20+
- Java 17+

### Build

```bash
# Android
cd android
./gradlew assembleRelease

# Windows
cd windows
npm run tauri build
```

### Authentication Setup

The app currently uses **Mock Authentication** for development. To use real OAuth:

1. **Create Firebase Project**
   - Go to [Firebase Console](https://console.firebase.google.com/)
   - Create new project "PQ Vault"

2. **Enable Authentication**
   - In Firebase Console, go to Authentication → Sign-in method
   - Enable Google, Apple, and Email/Password providers

3. **Download Configuration**
   - Download `google-services.json` from Firebase
   - Place it in `android/app/`

4. **Update Build Configuration**
   - In `android/build.gradle.kts`, add:
     ```
     plugins {
         id("com.google.gms.google-services") version "4.4.0" apply false
     }
     ```
   - In `android/app/build.gradle.kts`, add:
     ```
     plugins {
         id("com.google.gms.google-services")
     }
     ```

5. **Switch to Firebase Auth**
   - Replace `MockAuthManager` with `FirebaseAuthManager` in `AppModule.kt`
   - Add Firebase dependencies in `build.gradle.kts`

## 🔒 API Key Security

APK files can be decompiled, exposing embedded API keys. Mitigate this:

1. **Restrict API Key in Google Cloud Console:**
   - Go to **APIs & Services > Credentials**
   - Select your Web/Android API key
   - Set **Application restrictions**:
     - Android apps: Package name `com.quantvault.app`
     - Add your SHA-256 certificate fingerprint
   - Under **API restrictions**, limit to:
     - Firebase Auth API
     - Firebase Installations API

2. **Enable Firebase App Check:**
   - In Firebase Console, go to **App Check**
   - Register Android app with SafetyNet or Play Integrity
   - Enforce in Firebase Auth settings

3. **Key Rotation:**
   - Rotate exposed keys periodically
   - Use different keys per environment (dev/staging/prod)

## 📱 Screenshots

The app features a **glassy, professional UI** with:
- Gradient backgrounds (Blue → Purple → Pink)
- Frosted glass cards
- White text on dark gradients
- Smooth animations

## 🤝 Contributing

Contributions are welcome! Please read our contributing guidelines before submitting PRs.

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

---

**PQ Vault** - Secure your digital life with post-quantum cryptography 🛡️