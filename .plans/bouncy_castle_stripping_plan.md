# BouncyCastle Stripping Plan for Unity Integration

This plan details how to strip the BouncyCastle C# library **in-place** for use as a TLS client fallback in Unity projects (minimum Unity 2021.3 LTS). Stripping removes unused modules directly from this repository.

## Background

- **Source:** Full BouncyCastle.Cryptography library (2,154 C# files in `crypto/src/`)
- **Target:** Stripped **TLS client-only** subset (no server code)
- **Method:** In-place stripping (delete unused files from this repo)
- **Namespace Change:** `Org.BouncyCastle.*` → `TurboHTTP.SecureProtocol.Org.BouncyCastle.*`
- **Reason:** Prevent conflicts with other Unity plugins (Firebase, etc.) that use standard BouncyCastle

> [!IMPORTANT]
> Unity 2021.3 LTS uses .NET Standard 2.1 / .NET Framework 4.x. The BouncyCastle project targets `net6.0`, `netstandard2.0`, and `net461`, making `netstandard2.0` the compatible target.

---

## Phase 1: Module Identification & Dependency Mapping

### 1.1 Identify Required Modules for TLS Client

Based on the TLS implementation in `crypto/src/tls/`, the following module dependencies are required:

| Module | Files | Purpose | Keep? |
|--------|-------|---------|-------|
| `tls/` | 278 | TLS protocol implementation | ✅ **Required** |
| `crypto/` | 506 | Cryptographic primitives | ✅ **Required** (subset) |
| `asn1/` | 498 | ASN.1 encoding/decoding | ✅ **Required** (subset) |
| `math/` | 178 | Big integer, EC math | ✅ **Required** |
| `security/` | 28 | SecureRandom, key utils | ✅ **Required** |
| `x509/` | 32 | X.509 certificate parsing | ✅ **Required** |
| `util/` | 75 | Utility classes | ✅ **Required** |
| `runtime/` | 9 | Runtime intrinsics | ✅ **Required** |
| `pqc/` | 234 | Post-quantum crypto | ❌ **Exclude** |
| `bcpg/` | 83 | OpenPGP (email) | ❌ **Exclude** |
| `openpgp/` | 45 | OpenPGP high-level | ❌ **Exclude** |
| `cms/` | 63 | CMS/PKCS#7 | ❌ **Exclude** |
| `cmp/` | 10 | Certificate Management Protocol | ❌ **Exclude** |
| `crmf/` | 23 | Certificate Request Message Format | ❌ **Exclude** |
| `ocsp/` | 17 | OCSP (cert revocation) | ❌ **Exclude** |
| `tsp/` | 12 | Time Stamp Protocol | ❌ **Exclude** |
| `openssl/` | 9 | OpenSSL key format | ❌ **Exclude** |
| `pkcs/` | 14 | PKCS standards | ⚠️ **Partial** (PKCS1/5/8 only) |
| `pkix/` | 23 | X.509 extensions | ⚠️ **Partial** |
| `mozilla/` | 1 | Mozilla cert store | ❌ **Exclude** |
| `operators/` | 6 | High-level operators | ⚠️ **Review** |

### 1.2 Estimated Stripped Size

**Before stripping:** ~2,154 files  
**After stripping:** ~600-800 files (TLS + core crypto + ASN.1 + math + security + x509)  
**Reduction:** ~60-70%

---

## Phase 2: Source Code Preparation

### 2.1 Create Stripping Script

Create an Editor script that:
1. Copies required modules from BouncyCastle source
2. Transforms namespaces
3. Removes unnecessary files

#### [NEW] Editor/RepackageBouncyCastle.cs

```csharp
// One-time editor script to repackage BouncyCastle source
// Run via menu: TurboHTTP > Repackage BouncyCastle
```

### 2.2 Namespace Transformation

**Transform all files:**
```diff
- namespace Org.BouncyCastle.Tls
+ namespace TurboHTTP.SecureProtocol.Org.BouncyCastle.Tls
```

**Transform all using statements:**
```diff
- using Org.BouncyCastle.Crypto;
+ using TurboHTTP.SecureProtocol.Org.BouncyCastle.Crypto;
```

---

## Phase 3: Directory Structure in Target Unity Project

Per the `unity_proj_plan.md`, the target structure is:

```
Runtime/Transport/BouncyCastle/
    TurboHTTP.Transport.BouncyCastle.asmdef    ← New assembly definition
    TurboTlsClient.cs                           ← Custom TLS client wrapper
    TurboTlsAuthentication.cs                   ← Certificate validation
    BouncyCastleTlsProvider.cs                  ← ITlsProvider implementation
    Lib/                                        ← Stripped BouncyCastle source
        Org/
            BouncyCastle/
                Tls/                            # TLS implementation
                Crypto/                         # Core cryptography
                Asn1/                           # ASN.1 encoding
                Math/                           # Big integer & EC
                Security/                       # SecureRandom
                X509/                           # Certificate parsing
                Utilities/                      # Utility classes
```

---

## Phase 4: In-Place Stripping Process

> [!IMPORTANT]
> All stripping is done **in-place** in this repository. Delete files directly from `crypto/src/`.

### Step 4.1: Delete Excluded Modules

Delete these entire directories from `crypto/src/`:

```bash
rm -rf crypto/src/pqc      # Post-quantum crypto
rm -rf crypto/src/bcpg     # OpenPGP
rm -rf crypto/src/openpgp  # OpenPGP high-level
rm -rf crypto/src/cms      # CMS/PKCS#7
rm -rf crypto/src/cmp      # Certificate Management Protocol
rm -rf crypto/src/crmf     # Certificate Request Message Format
rm -rf crypto/src/ocsp     # OCSP
rm -rf crypto/src/tsp      # Time Stamp Protocol
rm -rf crypto/src/openssl  # OpenSSL key format
rm -rf crypto/src/mozilla  # Mozilla cert store
```

### Step 4.3: Namespace Transformation Script

Create a shell/python script to transform namespaces:

```bash
# Example: Find and replace in all .cs files
find Lib/ -name "*.cs" -exec sed -i '' \
  's/namespace Org\.BouncyCastle/namespace TurboHTTP.SecureProtocol.Org.BouncyCastle/g' {} \;

find Lib/ -name "*.cs" -exec sed -i '' \
  's/using Org\.BouncyCastle/using TurboHTTP.SecureProtocol.Org.BouncyCastle/g' {} \;
```

### Step 4.4: Remove Excluded Features from Crypto Module

From `crypto/` directory, **remove** these subdirectories that are not needed for TLS:

- `crypto/fpe/` — Format-preserving encryption (not used in TLS)
- `crypto/kems/` — KEM operations (post-quantum, not needed)

From `crypto/engines/`, keep only engines used by TLS cipher suites:
- `AesEngine`, `AesLightEngine` — AES
- `ChaCha7539Engine` — ChaCha20
- `SM4Engine` — SM4 (optional, for Chinese TLS)
- `CamelliaEngine` — Camellia (optional)

### Step 4.5: Remove Server-Only TLS Code (Required)

Remove all server-side TLS code (client-only build):
- `TlsServerProtocol.cs`
- `AbstractTlsServer.cs`
- `DefaultTlsServer.cs`
- `DtlsServerProtocol.cs`
- `TlsServer.cs`
- `TlsServerContext.cs`
- `TlsServerContextImpl.cs`
- `PskTlsServer.cs`
- `SrpTlsServer.cs`
- All `*Server*.cs` files in `tls/` directory
- All DTLS server files (`DtlsServer*`)

---

## Phase 5: Assembly Definition Setup

### [NEW] Runtime/Transport/BouncyCastle/TurboHTTP.Transport.BouncyCastle.asmdef

```json
{
    "name": "TurboHTTP.Transport.BouncyCastle",
    "rootNamespace": "TurboHTTP.SecureProtocol",
    "references": [],
    "includePlatforms": [],
    "excludePlatforms": [],
    "allowUnsafeCode": true,
    "overrideReferences": false,
    "precompiledReferences": [],
    "autoReferenced": false,
    "defineConstraints": [],
    "versionDefines": [],
    "noEngineReferences": true
}
```

**Key settings:**
- `allowUnsafeCode: true` — BouncyCastle uses unsafe for performance
- `autoReferenced: false` — Optional module, not auto-included
- `noEngineReferences: true` — Pure C#, no Unity Engine dependency

---

## Phase 6: IL2CPP / AOT Compatibility

### 6.1 Verify No Reflection Usage

BouncyCastle uses minimal reflection. Verify with:

```bash
grep -r "GetType()" Lib/ | grep -v "typeof"
grep -r "Activator.CreateInstance" Lib/
grep -r "Assembly.Load" Lib/
```

### 6.2 Link.xml (Preserve Required Types)

If stripping is too aggressive, add:

```xml
<!-- Runtime/Transport/BouncyCastle/link.xml -->
<linker>
    <assembly fullname="TurboHTTP.Transport.BouncyCastle" preserve="all"/>
</linker>
```

---

## Phase 7: Testing Strategy

### 7.1 Compile Test

```bash
# In Unity, verify no compile errors
# Menu: Assets > Open C# Project
# Build solution in IDE
```

### 7.2 Basic TLS Connection Test

Create a test script that:
1. Creates a BouncyCastle TLS client
2. Connects to `https://www.google.com`
3. Performs TLS handshake
4. Reads HTTP/1.1 response

### 7.3 Platform Testing Matrix

| Platform | Build Type | Expected Result |
|----------|------------|-----------------|
| Windows Editor | Mono | ✅ Pass |
| macOS Editor | Mono | ✅ Pass |
| Windows Standalone | IL2CPP | ✅ Pass |
| Android | IL2CPP | ✅ Pass |
| iOS | IL2CPP | ✅ Pass |
| WebGL | N/A | ❌ Not supported (use native TLS) |

---

## Summary: Implementation Checklist

- [ ] **Step 1:** Create target directory structure in Unity project
- [ ] **Step 2:** Copy required modules from BouncyCastle source
- [ ] **Step 3:** Run namespace transformation script on all files
- [ ] **Step 4:** Remove excluded modules (PGP, PQC, CMS, etc.)
- [ ] **Step 5:** Remove unused crypto engines (optional optimization)
- [ ] **Step 6:** Create assembly definition file
- [ ] **Step 7:** Create link.xml for IL2CPP
- [ ] **Step 8:** Test compilation in Unity Editor
- [ ] **Step 9:** Test TLS connection in Editor
- [ ] **Step 10:** Test IL2CPP build on target platforms

---

## Security Engineer Review

### 🔍 Security Audit Summary

This stripping plan is **architecturally sound** from a security perspective. The plan correctly identifies TLS-required modules and follows the proven BestHTTP approach. However, several cryptographic considerations must be addressed during implementation.

### 🚨 Critical Vulnerabilities

**No critical vulnerabilities in the plan itself.** However, the following MUST be enforced:

* **Issue:** Legacy cipher suite engines (3DES, DES) are marked as "keep" in Step 4.4
* **Why it's dangerous:** 3DES is deprecated (CVE-2016-2183 "Sweet32"), DES is broken (56-bit key)
* **Fix:** Remove `DesEngine.cs`, `DesEdeEngine.cs` OR restrict cipher suites in `TurboTlsClient`:
  ```csharp
  public override int[] GetCipherSuites() => new[] {
      CipherSuite.TLS_AES_128_GCM_SHA256,           // TLS 1.3
      CipherSuite.TLS_AES_256_GCM_SHA384,           // TLS 1.3
      CipherSuite.TLS_CHACHA20_POLY1305_SHA256,     // TLS 1.3
      CipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
      CipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
      // NO 3DES, NO CBC-only suites
  };
  ```

### ⚠️ Warnings & Best Practices

| Observation | Recommendation |
|-------------|----------------|
| **TLS Protocol Versions:** Plan doesn't specify minimum TLS version | Enforce TLS 1.2+ minimum. Disable TLS 1.0/1.1. |
| **Certificate Validation:** Plan mentions "basic validation only" | Ensure hostname verification is ALWAYS enabled. |
| **AES Mode Selection:** Plan keeps all crypto modes | Prefer AES-GCM over AES-CBC. Remove ECB mode files. |
| **Randomness:** BouncyCastle has its own SecureRandom | Verify it seeds from `System.Security.Cryptography.RandomNumberGenerator`. |
| **Memory Hygiene:** Key material in byte arrays | Add explicit `Array.Clear()` in key disposal paths. |

### ✅ Required Additions to Plan

**Step 4.4 — Remove Weak Crypto:**
```
crypto/engines/DesEngine.cs          → REMOVE
crypto/engines/RC4Engine.cs          → REMOVE  
crypto/modes/EcbBlockCipher.cs       → REMOVE (ECB is always insecure)
```

**Phase 7 — Security Test Cases:**
- Verify TLS 1.0/1.1 connections are **rejected**
- Verify invalid certificates are **rejected**
- Verify hostname mismatch is **rejected**
- Verify self-signed certs are **rejected** (unless explicitly allowed)

### Cryptographic Algorithm Checklist

| Algorithm | Status | Action |
|-----------|--------|--------|
| AES-GCM | ✅ Keep | Primary cipher |
| AES-CBC | ⚠️ Keep | Legacy fallback only |
| AES-ECB | ❌ Remove | Never secure |
| ChaCha20-Poly1305 | ✅ Keep | Modern alternative |
| 3DES | ❌ Remove | Deprecated (Sweet32) |
| DES | ❌ Remove | Broken |
| RC4 | ❌ Remove | Broken |
| SHA-256+ | ✅ Keep | Required |
| SHA-1 | ⚠️ Keep | Cert compatibility only |
| MD5 | ❌ Remove | Broken |
| RSA-2048+ | ✅ Keep | Minimum key size |
| ECDSA P-256+ | ✅ Keep | Preferred |

---

## Open Questions

1. **Target namespace:** Confirm `TurboHTTP.SecureProtocol.Org.BouncyCastle` is acceptable
2. **Expected final size:** ~500-600 files acceptable after removing server code + weak crypto?


