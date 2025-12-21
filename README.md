[![GoDoc](https://godoc.org/github.com/BottleFmt/gobottle?status.svg)](https://godoc.org/github.com/BottleFmt/gobottle)
[![CI](https://github.com/BottleFmt/gobottle/actions/workflows/ci.yml/badge.svg)](https://github.com/BottleFmt/gobottle/actions/workflows/ci.yml)

# gobottle

A comprehensive Go library for the Bottle RFC, providing layered message containers with encryption and signatures. Supports both classical (ECDSA, Ed25519, RSA) and post-quantum (ML-KEM, ML-DSA, SLH-DSA) cryptography.

## Installation

```bash
go get github.com/BottleFmt/gobottle
```

Requires Go 1.24 or later.

## Features

- **Bottle**: Layered message containers with encryption and signatures
- **ML-KEM**: Post-quantum encryption (ML-KEM-768, ML-KEM-1024) with optional X25519 hybrid mode
- **ML-DSA**: Post-quantum signatures (ML-DSA-44, ML-DSA-65, ML-DSA-87)
- **SLH-DSA**: Stateless hash-based post-quantum signatures (12 parameter sets)
- **ECDH Encryption**: Simple message encryption to ECDSA/ECDH keys
- **IDCard**: Identity management with sub-keys and key purposes
- **Keychain**: Secure key storage and management
- **Membership**: Cryptographically signed group memberships

## Bottle

Bottles are versatile containers for arbitrary data that support multiple layers of encryption and signatures. They can be serialized as CBOR or JSON.

### Creating and Opening Bottles

```go
import (
    "crypto/rand"
    "github.com/BottleFmt/gobottle"
)

// Create a bottle with a message
bottle := gobottle.NewBottle([]byte("secret message"))

// Encrypt for one or more recipients (any recipient can decrypt)
bottle.Encrypt(rand.Reader, bobPublicKey, alicePublicKey)

// Wrap in another layer to include encryption metadata in signature
bottle.BottleUp()

// Sign the bottle
bottle.Sign(rand.Reader, senderPrivateKey)

// Open the bottle (Bob decrypts)
opener, err := gobottle.NewOpener(bobPrivateKey)
message, info, err := opener.Open(bottle)

// Check who signed it
if info.SignedBy(senderPublicKey) {
    fmt.Println("Verified signature from sender")
}
fmt.Printf("Decryption layers: %d\n", info.Decryption)
```

### Bottle with Structured Data

```go
// Marshal Go structs directly into bottles
type MyData struct {
    Name  string `json:"name"`
    Value int    `json:"value"`
}

// CBOR encoding (compact, binary)
bottle, err := gobottle.Marshal(MyData{Name: "test", Value: 42})

// JSON encoding
bottle, err := gobottle.MarshalJson(MyData{Name: "test", Value: 42})

// Unmarshal from bottle
var data MyData
opener := gobottle.MustOpener(privateKey)
info, err := opener.Unmarshal(bottle, &data)
```

### Opening Encoded Bottles

```go
// Open CBOR-encoded bottle directly
message, info, err := opener.OpenCbor(cborBytes)

// Open from HTTP request (handles Content-Type)
message, info, err := opener.OpenHttp(httpRequest)
```

## ML-KEM Post-Quantum Encryption

ML-KEM (formerly CRYSTALS-Kyber) provides quantum-resistant key encapsulation. The library supports hybrid mode combining ML-KEM with X25519 for defense-in-depth.

### Key Generation

```go
// Generate ML-KEM-768 hybrid key (recommended)
privateKey, err := gobottle.GenerateMLKEMKey(rand.Reader, true)

// Generate ML-KEM-768 pure (no X25519)
privateKey, err := gobottle.GenerateMLKEMKey(rand.Reader, false)

// Generate ML-KEM-1024 for higher security
privateKey, err := gobottle.GenerateMLKEMKey1024(rand.Reader, true)
```

### Encryption and Decryption

```go
// Hybrid encryption (X25519 + ML-KEM)
ciphertext, err := gobottle.HybridEncrypt(rand.Reader, plaintext, publicKey)

// Pure ML-KEM encryption
ciphertext, err := gobottle.MLKEMEncrypt(rand.Reader, plaintext, publicKey)

// Decryption (auto-detects hybrid vs pure)
plaintext, err := gobottle.MLKEMDecrypt(ciphertext, privateKey)
```

### Using ML-KEM with Bottles

```go
// ML-KEM keys work seamlessly with bottles
mlkemKey, _ := gobottle.GenerateMLKEMKey(rand.Reader, true)

bottle := gobottle.NewBottle([]byte("quantum-safe message"))
bottle.Encrypt(rand.Reader, mlkemKey.Public())

// Mixed recipients (classical + post-quantum)
bottle.Encrypt(rand.Reader, ecdsaKey.Public(), mlkemKey.Public())
```

### Key Serialization

```go
// Marshal to PKCS#8 (private) / PKIX (public)
privDER, err := privateKey.MarshalPKCS8PrivateKey()
pubDER, err := publicKey.MarshalPKIXPublicKey()

// Parse from DER
privateKey, err := gobottle.ParseMLKEMPrivateKey(privDER)
publicKey, err := gobottle.ParseMLKEMPublicKey(pubDER)
```

## ML-DSA Post-Quantum Signatures

ML-DSA (Module-Lattice Digital Signature Algorithm, formerly CRYSTALS-Dilithium) provides quantum-resistant digital signatures. Three security levels are supported:

- **ML-DSA-44**: NIST security level 2 (comparable to AES-128)
- **ML-DSA-65**: NIST security level 3 (comparable to AES-192)
- **ML-DSA-87**: NIST security level 5 (comparable to AES-256)

### Key Generation

```go
import "github.com/KarpelesLab/mldsa"

// Generate ML-DSA-65 key (recommended)
key, err := mldsa.GenerateKey65(rand.Reader)

// Other variants
key44, err := mldsa.GenerateKey44(rand.Reader)  // Level 2
key87, err := mldsa.GenerateKey87(rand.Reader)  // Level 5
```

### Signing and Verification

```go
// Sign a message (ML-DSA signs messages directly, no pre-hashing)
signature, err := gobottle.Sign(rand.Reader, key, message)

// Verify signature
err = gobottle.Verify(key.PublicKey(), message, signature)

// Sign with context for domain separation
opts := &mldsa.SignerOpts{Context: []byte("my-application")}
signature, err := gobottle.Sign(rand.Reader, key, message, opts)
err = gobottle.Verify(key.PublicKey(), message, signature, opts)
```

### Using ML-DSA with Bottles

```go
// ML-DSA keys work seamlessly with bottles
key, _ := mldsa.GenerateKey65(rand.Reader)

bottle := gobottle.NewBottle([]byte("quantum-safe signed message"))
bottle.Sign(rand.Reader, key)

// Verify on open
opener := gobottle.MustOpener()
msg, info, err := opener.Open(bottle)
if info.SignedBy(key.PublicKey()) {
    fmt.Println("Verified ML-DSA signature")
}
```

### Key Serialization

```go
// Marshal to PKCS#8 (private) / PKIX (public)
privDER, err := gobottle.MarshalMLDSAPrivateKey(key)
pubDER, err := gobottle.MarshalPKIXPublicKey(key.PublicKey())

// Parse from DER
privateKey, err := gobottle.ParseMLDSAPrivateKey(privDER)
publicKey, err := gobottle.ParsePKIXPublicKey(pubDER)
```

## SLH-DSA Post-Quantum Signatures

SLH-DSA (Stateless Hash-Based Digital Signature Algorithm, also known as SPHINCS+) provides quantum-resistant digital signatures based on hash functions. It offers strong security guarantees without relying on lattice assumptions. Twelve parameter sets are supported:

**SHA2-based:**
- **SLH-DSA-SHA2-128s/128f**: NIST security level 1
- **SLH-DSA-SHA2-192s/192f**: NIST security level 3
- **SLH-DSA-SHA2-256s/256f**: NIST security level 5

**SHAKE-based:**
- **SLH-DSA-SHAKE-128s/128f**: NIST security level 1
- **SLH-DSA-SHAKE-192s/192f**: NIST security level 3
- **SLH-DSA-SHAKE-256s/256f**: NIST security level 5

The "s" variants are optimized for smaller signatures, while "f" variants are optimized for faster signing.

### Key Generation

```go
import "github.com/KarpelesLab/slhdsa"

// Generate SLH-DSA-SHA2-128s key (small signatures)
key, err := slhdsa.GenerateKey(rand.Reader, slhdsa.SHA2_128s)

// Generate SLH-DSA-SHA2-128f key (fast signing)
key, err := slhdsa.GenerateKey(rand.Reader, slhdsa.SHA2_128f)

// Higher security levels
key192, err := slhdsa.GenerateKey(rand.Reader, slhdsa.SHA2_192s)
key256, err := slhdsa.GenerateKey(rand.Reader, slhdsa.SHA2_256s)

// SHAKE-based variants
keyShake, err := slhdsa.GenerateKey(rand.Reader, slhdsa.SHAKE_128s)
```

### Signing and Verification

```go
// Sign a message (SLH-DSA signs messages directly, no pre-hashing)
signature, err := gobottle.Sign(rand.Reader, key, message)

// Verify signature
err = gobottle.Verify(key.Public(), message, signature)

// Sign with context for domain separation
opts := &slhdsa.Options{Context: []byte("my-application")}
signature, err := gobottle.Sign(rand.Reader, key, message, opts)
err = gobottle.Verify(key.Public(), message, signature, opts)
```

### Using SLH-DSA with Bottles

```go
// SLH-DSA keys work seamlessly with bottles
key, _ := slhdsa.GenerateKey(rand.Reader, slhdsa.SHA2_128s)

bottle := gobottle.NewBottle([]byte("hash-based signed message"))
bottle.Sign(rand.Reader, key)

// Verify on open
opener := gobottle.MustOpener()
msg, info, err := opener.Open(bottle)
if info.SignedBy(key.Public()) {
    fmt.Println("Verified SLH-DSA signature")
}
```

### Key Serialization

```go
// Marshal to PKCS#8 (private) / PKIX (public)
privDER, err := gobottle.MarshalSLHDSAPrivateKey(key)
pubDER, err := gobottle.MarshalPKIXPublicKey(key.Public())

// Parse from DER
privateKey, err := gobottle.ParseSLHDSAPrivateKey(privDER)
publicKey, err := gobottle.ParsePKIXPublicKey(pubDER)
```

## ECDH Message Encryption

Simple encryption to ECDSA/ECDH keys, supporting TPM and HSM backends through the `ECDHHandler` interface.

```go
// Encrypt to an ECDH public key
ciphertext, err := gobottle.ECDHEncrypt(rand.Reader, plaintext, ecdhPublicKey)

// Decrypt with private key (or any ECDHHandler)
plaintext, err := gobottle.ECDHDecrypt(ciphertext, ecdhPrivateKey)
```

## IDCard

IDCards allow entities to declare sub-keys with specific purposes (signing, decryption) and manage key lifecycles.

```go
// Create an IDCard for a signing key
idcard, err := gobottle.NewIDCard(signingKey.Public())

// Add metadata
idcard.Meta = map[string]string{"name": "Alice", "email": "alice@example.com"}

// Configure key purposes
idcard.SetKeyPurposes(signingKey.Public(), "sign", "decrypt")

// Add a dedicated encryption key
idcard.SetKeyPurposes(encryptionKey.Public(), "decrypt")
idcard.SetKeyDuration(encryptionKey.Public(), 365*24*time.Hour) // 1 year expiry

// Sign and serialize the IDCard
signedIDCard, err := idcard.Sign(rand.Reader, signingKey)

// Load and verify an IDCard
var loaded gobottle.IDCard
err = loaded.UnmarshalBinary(signedIDCard)

// Check key purposes
err = loaded.TestKeyPurpose(someKey, "sign")
if err != nil {
    fmt.Println("Key not authorized for signing")
}

// Get all keys for a purpose
decryptKeys := loaded.GetKeys("decrypt")
```

## Keychain

Keychain provides secure storage for private keys, indexed by their public key.

```go
// Create a keychain
kc := gobottle.NewKeychain()

// Add keys (supports ECDSA, Ed25519, RSA, ML-KEM)
kc.AddKey(ecdsaPrivateKey)
kc.AddKey(ed25519PrivateKey)
kc.AddKey(mlkemPrivateKey)

// Add multiple keys at once
kc.AddKeys(key1, key2, key3)

// Retrieve keys by public key
privateKey, err := kc.GetKey(publicKey)
signer, err := kc.GetSigner(publicKey)

// Sign with a specific key
signature, err := kc.Sign(rand.Reader, publicKey, message)

// Iterate over keys
for signer := range kc.Signers {
    fmt.Printf("Signer: %T\n", signer.Public())
}

// Use keychain with Opener
opener, err := gobottle.NewOpener(kc)
```

## Membership

Memberships provide cryptographically signed group affiliations.

```go
// Create a membership
membership := gobottle.NewMembership(memberIDCard, groupPublicKey)
membership.Info["role"] = "admin"

// Sign with group owner's key
err = membership.Sign(rand.Reader, groupOwnerKey)

// Verify membership
err = membership.Verify(groupIDCard)

// Add to IDCard
idcard.UpdateGroups([][]byte{membershipBytes})
```

## Signing and Verification

Low-level signing utilities that handle algorithm-specific requirements automatically.

```go
// Sign a message (hashing handled automatically)
signature, err := gobottle.Sign(rand.Reader, privateKey, message)

// Verify a signature
err = gobottle.Verify(publicKey, message, signature)
if err != nil {
    fmt.Println("Signature verification failed")
}
```

## Utility Functions

### PKIX Key Marshaling

Extended PKIX support including ML-KEM and ML-DSA keys:

```go
// Marshal any public key to PKIX format
der, err := gobottle.MarshalPKIXPublicKey(publicKey)

// Parse PKIX public key (supports ML-KEM, ML-DSA)
publicKey, err := gobottle.ParsePKIXPublicKey(der)
```

### Short Buffer Encryption

Encrypt small buffers (like AES keys) to various key types:

```go
// Encrypt a short buffer to any supported public key
encrypted, err := gobottle.EncryptShortBuffer(rand.Reader, aesKey, recipientPublicKey)

// Decrypt
decrypted, err := gobottle.DecryptShortBuffer(encrypted, recipientPrivateKey)
```

### Memory Clearing

Securely clear sensitive data from memory:

```go
privateKeyBytes := make([]byte, 32)
defer gobottle.MemClr(privateKeyBytes)
```

### Hashing

Helper for single or multi-level hashing:

```go
// Single hash
digest := gobottle.Hash(data, sha256.New)

// Multi-level hash (hash of hash)
digest := gobottle.Hash(data, sha256.New, sha256.New)
```

## Supported Key Types

| Type | Signing | Encryption | Post-Quantum |
|------|---------|------------|--------------|
| ECDSA (P-256, P-384, P-521) | ✓ | ✓ (via ECDH) | ✗ |
| Ed25519 | ✓ | ✓ (via X25519) | ✗ |
| RSA | ✓ | ✓ | ✗ |
| ML-KEM-768 | ✗ | ✓ | ✓ |
| ML-KEM-1024 | ✗ | ✓ | ✓ |
| ML-KEM + X25519 (Hybrid) | ✗ | ✓ | ✓ |
| ML-DSA-44/65/87 | ✓ | ✗ | ✓ |
| SLH-DSA (12 variants) | ✓ | ✗ | ✓ |

## Error Handling

```go
var (
    ErrNoAppropriateKey   // No key available to decrypt
    ErrVerifyFailed       // Signature verification failed
    ErrKeyNotFound        // Key not found in keychain/IDCard
    ErrGroupNotFound      // Group not found in IDCard
    ErrKeyUnfit           // Key not authorized for the operation
    ErrEncryptNoRecipient // No valid recipient for encryption
)
```

## License

See [LICENSE](LICENSE) file.
