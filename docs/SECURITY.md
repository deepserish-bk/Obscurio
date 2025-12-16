# Security Design

## Cryptographic Architecture

Obscurio uses a multi-layered security approach:

1. **Key Derivation**: Scrypt with parameters (N=16384, r=8, p=1)
   - Memory-hard function resistant to GPU/ASIC attacks
   - Salt ensures unique keys even with identical passwords

2. **Encryption**: AES-256-GCM
   - 256-bit key strength
   - Galois/Counter Mode provides authenticated encryption
   - Each encryption uses a unique nonce

3. **Storage**: JSON with base64 encoding
   - Encrypted payload stored as base64 string
   - Authentication tag stored alongside for integrity verification

## Threat Model

### Protected Against:
- File system access (encrypted at rest)
- Data tampering (GCM authentication)
- Brute-force attacks (Scrypt memory-hard KDF)
- Memory analysis (keys cleared when locked)

### Not Protected Against:
- Keyloggers on compromised systems
- Physical access to unlocked workstation
- Malware with memory scraping capabilities

## Best Practices

1. Use a strong master password (12+ characters, mixed character sets)
2. Enable auto-lock feature
3. Store backups in secure locations
4. Keep your operating system updated
