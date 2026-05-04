# Changelog

## [1.0.0] - 2024-05-04

### Added
- Post-quantum cryptography (ML-KEM-768, ML-DSA-65)
- Android app with Jetpack Compose
- Windows app with Tauri/React
- Glassy professional UI
- OAuth login (Google, Apple)
- Password generator (characters + passphrase)
- TOTP authenticator
- Passkey support (hybrid)
- P2P sync
- Behavioral fingerprinting
- Android Autofill service

### Security
- AES-256-GCM encryption
- ChaCha20-Poly1305 for sync
- Argon2id key derivation
- HKDF for key expansion
- Secure memory handling with zeroize

### Build
- All 4 ABIs for Android (armeabi-v7a, arm64-v8a, x86, x86_64)
- CI/CD with GitHub Actions
- Debug and Release builds

## [0.0.1] - 2024-01-01

### Added
- Initial project structure
- Rust core library skeleton
- Android Kotlin project setup