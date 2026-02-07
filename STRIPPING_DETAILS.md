# BouncyCastle Stripping Report

## 1. Executed Stripping Actions

The following actions have been performed to reduce the BouncyCastle library size and prepare it for Unity integration:

### 1.1 Module Removal
Removed entire functional modules (top-level directories) that are not required for a standard TLS client:
- **`pqc/`**: Post-Quantum Cryptography (ML-DSA, ML-KEM, SLH-DSA, etc.).
- **`bcpg/`**: OpenPGP implementation.
- **`openpgp/`**: High-level OpenPGP API.
- **`cms/`**: Cryptographic Message Syntax (PKCS#7).
- **`cmp/`**: Certificate Management Protocol.
- **`crmf/`**: Certificate Request Message Format.
- **`ocsp/`**: Online Certificate Status Protocol.
- **`tsp/`**: Time Stamp Protocol.
- **`openssl/`**: OpenSSL private key parsing utilities.
- **`mozilla/`**: Mozilla public key and store utilities.

### 1.2 Crypto Sub-module Removal
Removed specific cryptographic sub-directories:
- **`crypto/fpe/`**: Format-Preserving Encryption.
- **`crypto/kems/`**: Key Encapsulation Mechanisms (mostly PQC-related).

### 1.3 Weak & Legacy Engine Removal
Removed legacy or weak cipher engines:
- **DES / 3DES**: `DesEngine.cs`, `DesEdeEngine.cs`.
- **RC4**: `RC4Engine.cs`.

### 1.4 Code Modifications
Modified core factory and utility classes to remove references to the deleted PQC modules, fixing compilation errors:
- **`SignerUtilities.cs`**: Removed ML-DSA and SLH-DSA signer registrations.
- **`GeneratorUtilities.cs`**: Removed PQC key pair generator registrations.
- **`SubjectPublicKeyInfoFactory.cs`**: Removed PQC public key serialization logic.
- **`DefaultSignatureAlgorithmFinder.cs`**: Removed PQC algorithm IDs.
- **`DefaultDigestAlgorithmFinder.cs`**: Removed PQC digest mappings.
- **`GeneralName.cs`**: Fixed namespace alias referencing `Org.BouncyCastle`.
- **`BcDefaultTlsCredentialedDecryptor.cs`**: Fixed fully qualified namespace reference.

### 1.5 Namespace Transformation
Applied a global namespace and usage update to prevent conflicts with other BouncyCastle inclusions in Unity:
- **Namespace**: `Org.BouncyCastle` -> `TurboHTTP.SecureProtocol.Org.BouncyCastle`
- **Scope**: Applied to all `.cs` files, `using` directives, generic attributes, and string literals (reflection/configuration).

### 1.6 Verification
- **Status**: Compilation successful (`dotnet build`).
- **File Count**: Reduced from ~2,154 files to **1,591 files** (~26% reduction).

### 1.7 Aggressive Stripping (Client-Only Optimization)
Performed a second pass of aggressive stripping to further reduce size for mobile/Unity usage:
- **Server Code**: Removed `TlsServerProtocol`, `DefaultTlsServer`, `AbstractTlsServer`, and related classes.
- **Legacy/Unused Ciphers**: Removed Blowfish, CAST5, CAST6, Camellia, GOST, IDEA, RC2, RC5, RC6, SEED, Serpent, Skipjack, TEA, Twofish, XTEA, VMPC.
- **Unused ASN.1**: Removed definitions for CMP, CMS, CRM, OCSP, TSP, EAC, BSI, GOST, MISC, SMIME.
- **Verification**:
    - **Compilation**: Succeeded with `dotnet build`.
    - **Final File Count**: **1,349 files** (Total reduction of ~37% from original).

---

## 2. Analysis of Further Stripping Opportunities

Based on a scan of the remaining files, significant opportunities for further reduction exist.

### 2.1 TLS Server Code (High Impact)
The `crypto/src/tls` directory still contains full server-side implementation code. If this library is strictly for a **TLS Client**, the following are dead code:
- `TlsServerProtocol.cs`
- `DefaultTlsServer.cs`
- `AbstractTlsServer.cs`
- `ServerHello.cs` (logic related to constructing it)
- `NewSessionTicket.cs` (server-side generation)
- `TlsServerCertificate.cs`
- **DTLS**: `DtlsServerProtocol.cs` and related DTLS server logic.

### 2.2 Unused Cipher Engines (Very High Impact)
The `crypto/src/crypto/engines` directory still contains **59 files**, many of which are legacy or obscure ciphers not used in standard TLS 1.2/1.3.
- **Candidates for Removal**:
  - `BlowfishEngine.cs`
  - `Cast5Engine.cs`, `Cast6Engine.cs`
  - `CamelliaEngine.cs` (Optional)
  - `Dstu7624Engine.cs` (Ukrainian standard)
  - `GOST28147Engine.cs` (Russian standard)
  - `Grain128AEADEngine.cs`
  - `HC128Engine.cs`, `HC256Engine.cs`
  - `IdeaEngine.cs`
  - `ISAACEngine.cs`
  - `NaccacheSternEngine.cs`
  - `NoekeonEngine.cs`
  - `RC2Engine.cs`, `RC532Engine.cs`, `RC6Engine.cs`
  - `SEEDEngine.cs` (Korean standard)
  - `SerpentEngine.cs`
  - `SkipjackEngine.cs`
  - `SparkleEngine.cs`
  - `ThreefishEngine.cs`
  - `TwofishEngine.cs`
  - `TEAEngine.cs`, `XTEAEngine.cs`
  - `VMPCEngine.cs`

**Keep Only**: `AesEngine`, `ChaCha7539Engine` (for TLS 1.3), `RijndaelEngine` (maybe), and potentially `GcmBlockCipher` / `CcmBlockCipher` modes.

### 2.3 ASN.1 Definitions (Medium Impact)
The `crypto/src/asn1` directory contains subdirectories for protocols whose logic was removed. These are likely unused unless referenced by core X.509 parsing (unlikely for most).
- **Candidates for Removal**:
  - `asn1/cmp/` (49 files) - Certificate Management Protocol definitions.
  - `asn1/cms/` (52 files) - Cryptographic Message Syntax definitions.
  - `asn1/crmf/` (23 files) - Certificate Request Message Format.
  - `asn1/ocsp/` (17 files) - OCSP definitions.
  - `asn1/tsp/` (12 files) - Time Stamp Protocol definitions.
  - `asn1/misc/` (Netscape/Verisign legacy).
  - `asn1/smime/` (S/MIME).
  - `asn1/icao/` (Passport data).
  - `asn1/eac/` (Electronic Access Control).

### 2.4 Estimated Savings
- **Current Count**: 1,591 files.
- **Potential Further Reduction**:
  - Engines: ~40 files.
  - ASN.1: ~150+ files.
  - TLS Server: ~10-20 files.
- **Target Count**: ~1,300 files (Another ~15-20% reduction).
