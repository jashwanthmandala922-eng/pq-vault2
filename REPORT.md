# PQ Vault - Comprehensive Technical Report

## Executive Summary

**Project Name:** PQ Vault (Post-Quantum Password Manager)
**Version:** 1.0.0
**License:** MIT
**Platforms:** Android (Kotlin), Windows (Tauri/React), Core Library (Rust)

---

## 1. Project Overview

### 1.1 Purpose
PQ Vault is a post-quantum password manager designed to protect user credentials against both classical and quantum computer attacks. It uses NIST-approved post-quantum cryptographic algorithms (ML-KEM-1024, ML-DSA-87) with support for ML-KEM-768 and ML-DSA-65 as fallback options.

### 1.2 Core Philosophy
- **OAuth-only authentication** - No master password required; vault key derived from OAuth token
- **Dual-Key Hybrid Security** - Local PIN/biometric key combined with OAuth key via HKDF
- **Local-first storage** - User data never leaves device unless explicitly synced
- **Post-quantum security** - All encryption uses PQ algorithms
- **Cross-platform** - Android and Windows support

### 1.3 Dual-Key Security Model

PQ Vault implements a **defense-in-depth** strategy using a dual-key hybrid model:

```
OAuth Token (from Google/Apple)
           │
           ▼ HKDF ("pq-vault-master")
    Intermediate Key
           │
           ▼ (combined with)
    Local Key (PIN-derived or Biometric)
           │
           ▼ HKDF ("pq-vault-dual-key")
    Final Master Key
           │
           ▼ AES-256-GCM
    Vault Encryption
```

**Why Dual-Key?**
- If an attacker compromises the user's Google/Apple account, they still cannot access the vault without the local PIN
- Even if the device is stolen, the vault remains encrypted with a key derived from both factors
- Biometric integration provides convenient yet secure unlock

**Implementation:**
- PIN: 4-8 digits, Argon2id (256MB, 4 iterations) with salt
- Biometric: AES-256 key stored in Android Keystore, protected by biometric auth
- Local key encrypted with device-bound key before storage

### 1.4 Hardware-Backed Security (TPM/Keystore)

PQ Vault implements **device-bound security** using hardware security modules:

**Android (Keystore):**
- AES-256 key generated in secure hardware (TEE)
- Key never leaves the hardware - encryption/decryption happens inside
- Requires biometric or device credential for access
- Key bound to secure lock screen credentials

**Windows (TPM 2.0):**
- TPM-backed key handles for encryption
- PCR (Platform Configuration Registers) measurement for device state
- RSA-OAEP encryption with hardware-protected keys
- Key binding to TPM vendor ID and device state

**Security Model:**
```
Vault Salt
    │
    ├─► XOR with Hardware Salt (TPM/Keystore)
    │
    ▼
HKDF(Master Key + Hardware-Bound Salt)
    │
    ▼
Final Session Key (device-bound)
```

If the device is stolen:
- Software-only extraction impossible (key in hardware)
- Different device = different TPM/Keystore = different key
- Even with PIN, cannot decrypt without the original hardware

---

## 2. Architecture

### 2.1 Directory Structure

```
hiiiii/
├── securevault-core/           # Rust cryptographic library (30 files)
│   ├── src/
│   │   ├── lib.rs              # Main library entry
│   │   ├── error.rs            # Error handling
│   │   ├── generator.rs        # Password/passphrase generation
│   │   ├── oauth.rs           # OAuth token handling
│   │   ├── crypto/             # Cryptographic primitives
│   │   │   ├── mod.rs         # Crypto module exports
│   │   │   ├── aes.rs         # AES-256-GCM
│   │   │   ├── chacha20.rs    # ChaCha20-Poly1305
│   │   │   ├── kdf.rs        # HKDF, Argon2id
│   │   │   ├── ml_kem.rs     # ML-KEM-768/1024 (Kyber)
│   │   │   ├── ml_dsa.rs     # ML-DSA-44/65/87 (Dilithium)
│   │   │   ├── sha3.rs       # SHA-3, SHAKE256
│   │   │   └── rng.rs        # CSPRNG
│   │   ├── vault/              # Password vault
│   │   │   ├── mod.rs        # Vault struct, create/unlock
│   │   │   ├── entry.rs      # Entry types
│   │   │   └── crypto.rs     # Vault-specific crypto
│   │   ├── sync/              # P2P synchronization
│   │   │   ├── mod.rs        # Sync protocol
│   │   │   └── p2p.rs        # P2P connection
│   │   ├── behavior/          # Behavioral fingerprinting
│   │   │   ├── mod.rs
│   │   │   ├── analyzer.rs
│   │   │   ├── keystroke.rs
│   │   │   ├── gesture.rs
│   │   │   └── profile.rs
│   │   ├── passkey/           # WebAuthn/FIDO2
│   │   │   ├── mod.rs
│   │   │   ├── register.rs
│   │   │   └── authenticate.rs
│   │   ├── totp/              # TOTP generator
│   │   │   ├── mod.rs
│   │   │   ├── generator.rs
│   │   │   └── parser.rs
│   │   └── autofill/           # Android autofiller
│   │       ├── mod.rs
│   │       └── matcher.rs
│   └── Cargo.toml
│
├── android/                    # Android app (Kotlin)
│   ├── build.gradle.kts        # Root build
│   ├── settings.gradle.kts
│   ├── gradle.properties
│   └── app/
│       ├── build.gradle.kts   # App build config
│       ├── google-services.json # Firebase config
│       └── src/main/
│           ├── AndroidManifest.xml
│           ├── java/com/quantvault/app/
│           │   ├── PQVaultApplication.kt
│           │   ├── MainActivity.kt
│           │   ├── data/
│           │   │   ├── auth/
│           │   │   │   ├── FirebaseAuthManager.kt
│           │   │   │   └── MockAuthManager.kt
│           │   │   ├── local/
│           │   │   │   ├── SecurePreferences.kt
│           │   │   │   └── NativeVault.kt
│           │   │   └── repository/
│           │   │       ├── VaultRepository.kt
│           │   │       └── TOTPRepository.kt
│           │   ├── di/
│           │   │   └── AppModule.kt
│           │   ├── service/
│           │   │   └── PQVaultAutofillService.kt
│           │   └── ui/
│           │       ├── PQVaultApp.kt
│           │       ├── theme/
│           │       │   ├── Theme.kt
│           │       │   ├── Color.kt
│           │       │   └── Typography.kt
│           │       ├── components/
│           │       │   ├── GlassCard.kt
│           │       │   ├── OAuthButtons.kt
│           │       │   └── BottomNavBar.kt
│           │       ├── navigation/
│           │       │   └── NavGraph.kt
│           │       └── screens/
│           │           ├── auth/
│           │           │   ├── LoginScreen.kt
│           │           │   ├── LoginViewModel.kt
│           │           │   └── AuthViewModel.kt
│           │           ├── vault/
│           │           │   ├── VaultScreen.kt
│           │           │   ├── AddEntryScreen.kt
│           │           │   └── VaultViewModel.kt
│           │           ├── authenticator/
│           │           │   └── AuthenticatorScreen.kt
│           │           ├── generator/
│           │           │   └── GeneratorScreen.kt
│           │           ├── sync/
│           │           │   └── SyncScreen.kt
│           │           ├── passkey/
│           │           │   └── PasskeyScreen.kt
│           │           └── settings/
│           │               └── SettingsScreen.kt
│           ├── res/
│           │   ├── values/
│           │   │   ├── strings.xml
│           │   │   ├── colors.xml
│           │   │   └── themes.xml
│           │   ├── drawable/
│           │   │   └── ic_launcher_foreground.xml
│           │   └── xml/
│           │       └── autofill_service.xml
│           └── cpp/
│               ├── CMakeLists.txt
│               └── pqvault_jni.cpp
│
├── windows/                   # Windows app (Tauri/React)
│   ├── package.json
│   ├── vite.config.ts
│   ├── tailwind.config.js
│   ├── tsconfig.json
│   ├── index.html
│   ├── src/
│   │   ├── main.tsx
│   │   ├── App.tsx
│   │   ├── index.css
│   │   ├── components/
│   │   │   ├── AuthenticatorPanel.tsx
│   │   │   └── PasswordGenerator.tsx
│   │   └── hooks/
│   │       ├── useVault.ts
│   │       └── usePasswordGenerator.ts
│   └── src-tauri/
│       ├── Cargo.toml
│       ├── build.rs
│       ├── tauri.conf.json
│       ├── src/
│       │   ├── main.rs
│       │   ├── lib.rs
│       │   └── commands.rs
│
├── .github/workflows/
│   ├── android.yml
│   ├── windows.yml
│   └── release.yml
│
├── README.md
├── CHANGELOG.md
├── LICENSE
└── .gitignore
```

---

## 3. Cryptographic Implementation

### 3.1 Algorithms Used

| Algorithm | Type | Purpose | NIST Security Level |
|-----------|------|---------|---------------------|
| ML-KEM-1024 | KEM | Key encapsulation (default) | 192-bit (Category 5) |
| ML-KEM-768 | KEM | Key encapsulation (fallback) | 128-bit (Category 3) |
| ML-DSA-87 | Signature | Digital signatures (default) | 256-bit (Category 5) |
| ML-DSA-65 | Signature | Digital signatures (fallback) | 192-bit (Category 3) |
| AES-256-GCM | AEAD | Symmetric encryption | 256-bit |
| ChaCha20-Poly1305 | AEAD | P2P sync encryption | 256-bit |
| HKDF | KDF | Key derivation | 256-bit |
| Argon2id | KDF | Password hardening (256MB) | 256-bit |
| SHA-3-256/512 | Hash | Hashing | 256/512-bit |

### 3.2 Key Hierarchy

```
OAuth Token (from Google/Apple)
       │
       ▼
   HKDF("pq-vault-master") → Master Key (32 bytes)
       │
       ├──► HKDF("pq-vault-session", Salt) → Session Key (32 bytes)
       │       │
       │       ▼
       │   AES-256-GCM → Vault Encryption
       │
       └──► ML-KEM-768 → Encrypted session key (for P2P sync)
```

### 3.3 Crypto Module Details

**liboqs Integration:**
- Uses liboqs 0.9.0 for post-quantum operations
- ML-KEM-1024: 1568-byte public key, 3168-byte secret key, 1568-byte ciphertext (default)
- ML-KEM-768: 1184-byte public key, 2400-byte secret key, 1088-byte ciphertext (fallback)
- ML-DSA-65: 1952-byte public key, 4000-byte secret key, 3293-byte signature

**Symmetric Encryption:**
- AES-256-GCM with random 12-byte nonce per encryption
- ChaCha20-Poly1305 for P2P sync (also 12-byte nonce)

**Key Derivation:**
- HKDF (RFC 5869) with SHA-256
- Argon2id (m=262144 = 256MB, t=4, p=4) for password hardening

---

## 4. Feature Implementation

### 4.1 Vault Management

**Data Structure:**
```rust
struct Vault {
    version: u8,
    id: Uuid,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    entries: Vec<Entry>,
    folders: Vec<Folder>,
    settings: VaultSettings,
}

struct Entry {
    id: Uuid,
    entry_type: EntryType, // Password, TOTP, SecureNote, Passkey
    title: String,
    url: Option<String>,
    username: Option<String>,
    password: Option<String>,
    notes: Option<String>,
    totp_secret: Option<String>,
    favorite: bool,
    created_at: DateTime<Utc>,
    updated_at: DateTime<Utc>,
    custom_fields: Vec<CustomField>,
}
```

**Storage:**
- Android: SharedPreferences encrypted vault data
- Data stored as Base64-encoded byte arrays

### 4.1.1 Full Metadata Encryption

PQ Vault encrypts **ALL** entry data, including traditionally "non-sensitive" metadata:

**Encrypted Fields:**
| Field | Why It Matters |
|-------|----------------|
| Entry ID | Reveals total entry count (target value) |
| Title | Reveals service usage (e.g., "Binance", "Kraken" = crypto target) |
| URL | Direct digital footprint - reveals accounts user has |
| Username | Email/username = target for phishing |
| Notes | May contain 2FA backup codes, recovery info |
| Entry Type | Password vs SecureNote vs Card = asset type |
| Favorite | High-value target indicator |
| Custom Fields | Any user-defined sensitive data |

**Encryption Architecture:**
```
Plaintext Entry
    │
    ├─► id: "uuid-123" ──────► EncryptedField (AES-256-GCM)
    ├─► title: "Binance" ────► EncryptedField
    ├─► url: "binance.com" ──► EncryptedField  
    ├─► username: "a@b.c" ────► EncryptedField
    ├─► password: "***" ─────► EncryptedField
    ├─► notes: "2FA: ***" ───► EncryptedField
    ├─► favorite: "true" ───► EncryptedField
    └─► custom_fields ───────► EncryptedField[]
```

**Implementation (Android):**
```kotlin
class MetadataEncryptor(sessionKey: ByteArray) {
    fun encryptEntry(entry: VaultEntry): EncryptedVaultEntry
    fun decryptEntry(encrypted: EncryptedVaultEntry): VaultEntry
    fun serializeEncryptedEntry(entry): ByteArray
    fun deserializeEncryptedEntry(data): VaultEntry
}

data class EncryptedField(
    val cipherText: ByteArray,  // AES encrypted
    val nonce: ByteArray,        // GCM nonce
    val tag: ByteArray          // Authentication tag
)
```

**Why This Matters:**
- URL "binance.com" → attacker knows user has crypto account
- URL "kraken.io" → attacker knows user has crypto account
- URL "bankofamerica.com" → attacker knows user has US bank
- Any URL → digital footprint = social engineering goldmine
- Entry count → attacker knows how "valuable" device might be

**Defense:**
Even if vault is leaked, attacker sees ONLY encrypted blobs - cannot determine:
- How many accounts user has
- What services user uses
- Which accounts might be high-value (crypto, banking)
- Session key kept in memory only, zeroized on lock

### 4.2 P2P Synchronization

**Protocol:**
- Uses UDP broadcast for device discovery (port 53535)
- TCP (port 53536) for actual sync
- ChaCha20-Poly1305 for data encryption
- Session key exchange via ML-KEM-768

**Mutual Authentication (MitM Prevention):**

To prevent Man-in-the-Middle attacks during P2P sync, PQ Vault implements mutual authentication:

1. **DH Key Exchange**: Both devices generate ephemeral Diffie-Hellman key pairs
2. **QR Code Exchange**: Device A shows QR with device ID + public key
3. **SAS Verification**: Both devices compute identical Short Authentication String (6 digits)
4. **Out-of-Band Verification**: Users manually compare SAS codes
5. **Shared Secret Derivation**: DH shared secret → SHA-256 → AES key

**Authentication Flow:**
```
Device A                          Device B
   |                                 |
   |--- Show QR (ID + PubKey) ----->|
   |                                 |
   |--- Scan QR (ID + PubKey) ----->|
   |                                 |
   |--- Compute SAS (both same) ----|
   |                                 |
   |--- User verifies SAS match ----|
   |                                 |
   |--- Sync with DH-derived key ---|
   |                                 |
   |--- Encrypted data transfer ----|
```

**Security:**
- SAS derived from: DH_secret + device_ID_A + device_ID_B
- If MitM intercepts, they cannot compute same SAS (no DH secret)
- Rejected if SAS doesn't match → connection terminated

**Sync Algorithm:**
1. Discover peers on local network (UDP broadcast)
2. Exchange public keys via QR codes
3. Derive shared secret → compute SAS
4. User verifies SAS matches on both devices
5. Establish encrypted TCP channel
6. Transfer vault data (encrypted with DH-derived key)
7. Verify integrity via MAC

### 4.2.1 Perfect Forward Secrecy (PFS)

PQ Vault implements **Perfect Forward Secrecy** for all P2P sync sessions:

**Key Ratchet Mechanism:**
- Each message encrypted with unique message key
- Message keys derived from shared secret + counter using HMAC-SHA256
- Chain key ratchets forward after each message
- Previous message keys never reused

**PFS Implementation:**
```kotlin
// Per-message key derivation
chainKey = HMAC-SHA256(chainKey, "chain_key" || counter || "pfs_ratchet")
messageKey = HMAC-SHA256(chainKey, "message_key" || counter)
ciphertext = AES-256-GCM(messageKey, nonce, plaintext)
```

**Security Properties:**
- If one message key is compromised, only that message is exposed
- Past messages use different keys → not decryptable
- Future messages use different keys → not decryptable
- Replay attacks prevented by message counter verification

**Key Rotation:**
- Message counter increments per message
- Chain key updated via one-way function
- No way to derive previous keys from current state

**Protocol:**
```
Message 1: Key_1 = f(secret, 1) → Encrypt(Data_1) → Counter=1
Message 2: Key_2 = f(Key_1, 2) → Encrypt(Data_2) → Counter=2
Message 3: Key_3 = f(Key_2, 3) → Encrypt(Data_3) → Counter=3
...
```

Even if an attacker:
- Intercepts a message → Can only decrypt that one message
- Compromises a key → Cannot access past/future messages
- Performs offline attack → Must crack each message individually

---

## 4.3 TOTP Authenticator

### 4.3 TOTP Authenticator

- Implements RFC 6238 TOTP
- 6-digit codes, 30-second period
- Supports 8-digit codes, custom periods
- Base32 secret encoding
- HMAC-SHA1 algorithm

### 4.4 Passkey Support

- Hybrid approach: ECDSA (P-256) + ML-DSA-65
- FIDO2/WebAuthn compliant
- Platform authenticator integration
- Keys stored in vault as encrypted entries

### 4.5 Password Generator

**Character-mode options:**
- Length: 4-128 characters
- Uppercase (A-Z)
- Lowercase (a-z)
- Numbers (0-9)
- Symbols (!@#$%^&*...)
- Exclude ambiguous (0, O, l, 1)

**Passphrase-mode options:**
- Word count: 4-12
- Separator: space, hyphen, dot
- Capitalize first letter
- Include number

### 4.6 Autofill Service

- Android AutofillService implementation
- URL-based field matching
- Whitelist/blacklist domains
- Responsive autofill for apps and browsers

### 4.7 Behavioral Fingerprinting

**Analyzes:**
- Keystroke dynamics (timing between key presses)
- Mouse/touch gestures (velocity, acceleration)
- Typing speed patterns

**Creates:**
- Behavioral profile per user
- Used as secondary authentication factor
- Score: 0-100 confidence level

---

## 5. Android Application

### 5.1 Build Configuration

**Gradle Configuration:**
- Namespace: `com.quantvault.app`
- Min SDK: 26 (Android 8.0)
- Target SDK: 34 (Android 14)
- Kotlin: 1.9.20
- Compose: 1.5.4

**Dependencies:**
- Hilt 2.48 (DI)
- Firebase Auth 32.7.0
- Navigation Compose 2.7.5
- Material3 1.1.x
- Biometric 1.1.0
- ML Kit Barcode (QR scanning)
- CameraX (QR scanning)

**NDK Configuration:**
- ABI: armeabi-v7a, arm64-v8a, x86, x86_64
- STL: c++_shared
- C++17 standard

### 5.2 UI Components

**Theme:**
- Dark mode only
- Background: #0D1117 (GitHub dark)
- Surface: #161B22
- Accent: #58A6FF (Blue)

**UI Components:**
- GlassCard: Frosted glass effect with gradient
- BottomNavBar: 4 tabs (Vault, Auth, Sync, Settings)
- OAuthButtons: Google sign-in with glass effect

**Screens:**
1. LoginScreen - OAuth login with Firebase
2. VaultScreen - Password entries list
3. AddEntryScreen - Create/edit entries
4. AuthenticatorScreen - TOTP codes
5. GeneratorScreen - Password generator
6. SyncScreen - P2P device management
7. PasskeyScreen - Passkey registration
8. SettingsScreen - App preferences

### 5.3 Dependency Injection (Hilt)

**Providers:**
- SecurePreferences (SharedPreferences wrapper)
- NativeVault (JNI bridge to Rust core)
- VaultRepository (vault operations)
- TOTPRepository (TOTP generation)
- FirebaseAuthManager (OAuth)
- FirebaseAuth (Firebase SDK)

### 5.4 Autofill Service

**Manifest Configuration:**
- Service: PQVaultAutofillService
- Permission: BIND_AUTOFILL_SERVICE
- Intent filter for autofill

**Capabilities:**
- Dataset generation for username/password
- Field detection and matching
- Save new credentials

---

## 6. Windows Application

### 6.1 Technology Stack

- **Frontend:** React 18, TypeScript, Tailwind CSS
- **Backend:** Tauri 2.0 (Rust)
- **State Management:** Zustand

### 6.2 Tauri Configuration

```json
{
  "productName": "PQ Vault",
  "identifier": "com.pqvault.app",
  "build": {
    "devtools": true
  },
  "app": {
    "windows": [
      {
        "title": "PQ Vault",
        "width": 900,
        "height": 700,
        "resizable": true
      }
    ]
  }
}
```

### 6.3 Commands (Tauri IPC)

- `init_vault(oauth_token)` - Create new vault
- `unlock_vault(oauth_token)` - Unlock existing vault
- `lock_vault()` - Lock vault
- `add_entry(entry)` - Add password entry
- `get_entries()` - List all entries
- `generate_password(options)` - Generate password
- `generate_totp(secret)` - Generate TOTP code
- `sync_devices()` - Initiate P2P sync

### 6.4 Tauri Security

**Isolation Mode:**
- `withGlobalTauri: false` - Prevents global access to Tauri API
- CSP (Content Security Policy) enforced:
  - `default-src 'self'` - Only same-origin
  - `script-src 'self'` - No inline scripts
  - `connect-src 'self' ipc:` - Only IPC allowed

**IPC Schema Validation:**
- Every command input validated against registered schema
- Length constraints (min/max) enforced
- Input sanitization (XSS prevention)
- URL validation for web URLs
- Password strength requirements

**Security Module (Rust):**
```rust
pub fn validate_command_input(command: &str, payload: &Value) -> Result<()>
pub fn sanitize_string(input: &str) -> String
pub fn validate_url(url: &str) -> bool
pub fn validate_password_strength(password: &str) -> Result<()>
```

**Command Validation Rules:**
| Command | Field | Constraint |
|---------|-------|-------------|
| unlock_vault | password | 8-128 chars |
| create_vault | password | 12+ chars, complex |
| add_entry | title | 1-100 chars |
| add_entry | url | max 2048, valid URL |
| add_entry | password | max 4096 chars |
| generate_password | length | 4-128 |

**Frontend Security (React):**
- All Tauri calls go through `secureVault` wrapper
- Errors converted to typed `SecureAPIError`
- No direct `invoke()` calls in components

---

## 7. Authentication Flow

### 7.1 OAuth-Only Authentication

**Flow:**
1. User taps "Continue with Google"
2. Firebase Google Sign-In UI appears
3. User authenticates with Google
4. Firebase returns OAuth token/ID token
5. App derives master key from token using HKDF
6. Vault unlocked with derived key
7. Session key kept in memory

**Token Handling:**
- OAuth access token used as key derivation material
- Stored in memory only, never persisted
- Session key zeroized on app background/lock

### 7.2 Firebase Integration

**Configuration:**
- Project ID: `quant-locker`
- Package: `com.quantvault.app`
- Web Client ID: `637945006038-bkem8vu8md85s5tgs94gojpkrvfurfk4`

**Auth Providers:**
- Google Sign-In
- Email/Password (optional)
- Apple Sign-In (future)

---

## 8. CI/CD Pipelines

### 8.1 Android Workflow (.github/workflows/android.yml)

**Triggers:** Push to main, PR
**Jobs:**
- Build with Gradle
- Run unit tests
- Build release APK

### 8.2 Windows Workflow (.github/workflows/windows.yml)

**Triggers:** Push to main, PR
**Jobs:**
- Install Rust
- Install Node.js
- Build with Tauri
- Run tests

### 8.3 Release Workflow (.github/workflows/release.yml)

**Triggers:** New tag
**Jobs:**
- Build Android APK
- Build Windows EXE
- Create GitHub release
- Upload artifacts

---

## 9. Security Considerations

### 9.1 API Key Protection

- **Restrict in Google Cloud Console:**
  - Package name: `com.quantvault.app`
  - SHA-256 fingerprint required
  - API restrictions: Firebase Auth API, Firebase Installations API

- **Firebase App Check:**
  - Register Android with SafetyNet/Play Integrity
  - Enforce in Firebase Auth settings

### 9.2 Code Security

- R8 minification and obfuscation enabled
- All 4 ABIs included for compatibility
- ProGuard rules for security-sensitive classes
- Source code review required

### 9.3 Tamper Detection & Integrity Verification

PQ Vault implements multi-layer tamper detection:

**R8 Obfuscation:**
- Enabled minification for release builds
- Class name obfuscation for JNI bridges
- Method inlining enabled for performance
- Debug logging stripped at compile time
- Security-critical classes explicitly preserved

**Runtime Integrity Checks:**
- Debug mode detection (blocks release builds on debug devices)
- Root detection (common paths + root app detection)
- Emulator detection (QEMU, hardware fingerprints)
- Hook detection (Xposed, Substrate, FRIDA)
- SafetyNet/Play Integrity API attestation

**Security Actions:**
| Condition | Action |
|-----------|--------|
| Hooks detected | BLOCK - Immediately block vault access |
| SafetyNet fails | BLOCK - Cannot verify device integrity |
| Device rooted | RESTRICT - Limit functionality |
| Emulator detected | RESTRICT - Disable P2P sync |
| Test device | ALLOW - Development continues |

**Security Score (0-100):**
- -30 for root detection
- -40 for hook detection
- -20 for emulator
- -40 for failed integrity
- Final score affects allowed operations

**App Lifecycle:**
- Integrity check runs on app startup
- Background → foreground re-verification optional
- Security state persisted in memory only

### 9.3 Formal Zeroization

PQ Vault implements **formal zeroization** to ensure sensitive data cannot remain in memory after use:

**Zeroize Crate Usage:**
- All session keys, master keys, and sensitive buffers use the `zeroize` crate
- Prevents compiler from optimizing away memory-clearing operations
- Uses volatile writes and inline assembly where needed

**Secure Memory Types:**
- `SecureVec<T>` - Vector that zeroizes on drop
- `SecureString` - String that zeroizes on drop
- `SessionKey` - 256-bit key with automatic zeroization
- `MasterKey` - 512-bit key with automatic zeroization
- `SecureArray<N>` - Fixed-size arrays with secure clearing

**Implementation:**
```rust
// Session key automatically zeroized when UnlockedVault is dropped
pub struct UnlockedVault {
    pub vault: Vault,
    session_key: SecureVec, // Zeroizing wrapper
}

impl Drop for UnlockedVault {
    fn drop(&mut self) {
        // SecureVec's Drop calls zeroize() - cannot be optimized away
        self.session_key.secure_zero();
    }
}
```

**Key Zeroization Points:**
- Vault lock/unlock operations
- P2P session key rotation
- Password/PIN entry handling
- TOTP secret storage

---

## 10. Build Process

### 10.1 Android Build

```bash
cd android
./gradlew assembleRelease
# Output: app/build/outputs/apk/release/app-release.apk
```

**APK Size Target:** >50MB (native libraries + all ABIs)

### 10.2 Windows Build

```bash
cd windows
npm run tauri build
# Output: src-tauri/target/release/pq-vault.exe
```

### 10.3 Native Library Build (Rust)

```bash
cd securevault-core
cargo build --release
# Output: target/release/libsecurevault_core.so
```

---

## 11. Testing

### 11.1 Unit Tests (Rust)

- Crypto encrypt/decrypt
- Vault create/unlock
- Vault add/delete entries
- TOTP generation

### 11.2 Integration Tests (Android)

- OAuth flow
- Vault operations
- UI rendering

### 11.3 Manual Testing

- P2P sync
- Autofill service
- Biometric unlock

---

## 12. Dependencies

### 12.1 Rust (securevault-core)

| Package | Version | Purpose |
|---------|---------|---------|
| liboqs | 0.9 | Post-quantum crypto |
| ring | 0.17 | Classic crypto |
| aes-gcm | 0.10 | AES encryption |
| chacha20poly1305 | 0.10 | ChaCha20 encryption |
| argon2 | 0.5 | Password hashing |
| tokio | 1.36 | Async runtime |
| serde | 1.0 | Serialization |
| uuid | 1.8 | UUID generation |

### 12.2 Android (Kotlin)

| Package | Version | Purpose |
|---------|---------|---------|
| Compose BOM | 2023.10.01 | UI framework |
| Hilt | 2.48 | Dependency injection |
| Navigation Compose | 2.7.5 | Screen navigation |
| Firebase Auth | 32.7.0 | OAuth authentication |
| Biometric | 1.1.0 | Fingerprint unlock |
| ML Kit Barcode | 17.2.0 | QR code scanning |

### 12.3 Windows (React/TypeScript)

| Package | Version | Purpose |
|---------|---------|---------|
| React | 18.2.0 | UI framework |
| Tauri | 2.0 | Desktop framework |
| Zustand | 4.4.7 | State management |
| Tailwind | 3.3.6 | CSS framework |
| TypeScript | 5.3.3 | Type safety |

---

## 13. Error Handling

### 13.1 Error Types (Rust)

```rust
pub enum Error {
    Crypto(String),
    Vault(String),
    EntryNotFound(String),
    Sync(String),
    Io(String),
    Serde(String),
}
```

### 13.2 Error Handling (Kotlin)

- Result wrapper for all async operations
- Exception handling in ViewModels
- User-friendly error messages in UI

---

## 14. Performance

### 14.1 Benchmarks (Rust)

Included criterion benchmarks:
- `crypto` benchmark - encryption throughput

### 14.2 Optimizations

- Zero-copy deserialization where possible
- Async I/O for file operations
- Lazy loading for vault entries
- Image caching in Compose

---

## 15. Future Enhancements

### 15.1 Planned Features

- [ ] iOS application
- [ ] Browser extension (Chrome/Firefox)
- [ ] Cloud backup (encrypted)
- [ ] Import from other password managers
- [ ] Password health analysis
- [ ] Breach monitoring integration

### 15.2 Research Topics

- Post-quantum threshold signatures
- MPC-based secret sharing
- Privacy-preserving sync

---

## 16. Appendix

### 16.1 File Sizes

- Source code: ~508KB (Rust) + ~200KB (Kotlin) + ~150KB (TypeScript)
- Target APK: >50MB (with native libs for all ABIs)
- Target EXE: ~10MB (Windows)

### 16.2 Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2024 | Initial release |

### 16.3 Credits

- **Team:** SecureVault Team
- **Cryptography:** liboqs (Dr. Douglas Stebila)
- **Icons:** Material Design Icons

---

## 17. Conclusion

PQ Vault implements a comprehensive post-quantum password management system with:

1. **Strong encryption** using NIST-approved PQ algorithms
2. **Modern UX** with glassmorphic design
3. **Cross-platform** support (Android, Windows)
4. **Open source** transparency
5. **Security-first** architecture

The codebase follows best practices for:
- Clean architecture (separation of concerns)
- Test-driven development
- Type-safe implementations
- Comprehensive documentation

This report documents every minute detail of the PQ Vault application, providing a complete technical reference for developers, security researchers, and users.