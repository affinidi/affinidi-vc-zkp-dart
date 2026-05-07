# Affinidi VCs for ZKPs

The Affinidi VCs for ZKPs package provides a specialized Dart SDK for implementing untraceable Zero-Knowledge Proof Verifiable Credential (ZK-VC) workflows. This library enables issuers to create and sign VC data, holders to prepare deterministic circuit inputs, and allows verifiers to run local document checks for testing and integration.

> **⚠️ IMPORTANT SECURITY AND PRIVACY NOTE:**
> This package is a cryptographic tool and does not process personal data outside of the structured data defined by the user. When integrated into a broader system that handles personally identifiable information (PII), users are solely responsible for ensuring that the entire use case complies with all applicable privacy laws and data protection obligations (e.g., GDPR).

**Protocol Guide:**
While the library provides implementation tools, we encourage you to start by exploring the **[Protocol Documentation](doc/protocol.md)**. Understanding the overall protocol flow, credential layout, and the structure of Untraceable-ZK-VC circuits will provide the necessary context for successful development.

## Table of Contents

- [Core Concepts](#core-concepts)
- [ZK-VC Workflow Overview](#zk-vc-workflow-overview)
- [Supported Crypto & Key Management](#supported-crypto--key-management)
- [Commitment & Data Integrity](#commitment--data-integrity)
- [Signed VC Document Format](#signed-vc-document-format)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
- [Testing & Native Symbols](#testing--native-symbols)
- [Support & Feedback](#support--feedback)
- [Contributing](#contributing)

## Core Concepts

The ZK-VC model enhances traditional SSI by leveraging advanced cryptography for maximum privacy.

- **Verifiable Credential (VC):** A cryptographically signed digital claim. Unlike standard VCs, the goal of the ZK-VC process is not to reveal the data, but to prove knowledge of the data's existence.
- **Zero-Knowledge Proof (ZKP):** A cryptographic method allowing a Prover (the holder) to prove possession of a secret or knowledge (e.g., "I am over 18") to a Verifier without revealing the underlying secret (the actual birthdate).
- **Commitment:** A process of cryptographically binding structural elements (field name, type, value) into a single hash. This is crucial for ensuring the inputs are canonical and tamper-proof throughout the ZKP process.
- **Poseidon Hash:** A permutation-based hash function optimized for algebraic circuit mathematics. It is used as the primary hashing mechanism for generating deterministic commitments within the ZK context.

## ZK-VC Workflow Overview

The lifecycle of a ZK-VC involves three distinct, highly controlled stages:

1. **Issuer Flow (Creation):** The Issuer creates the VC by generating structural commitments, calculating the final unique digest, and signing this digest using **EdDSA**.
2. **Holder Flow (Preparation):** The Holder extracts the required commitment components and prepares them into a flat witness map (`HolderCircuitInputs`) suitable for consumption by the ZK prover circuit.
3. **Verifier Flow (Validation):** In a production environment, the verifier receives *only* the ZKP presentation and the resulting proof, **not** the full document. The tools provided in this library (`VcVerifier`) are intended strictly for local debugging, comprehensive testing, and integration checks.

## Supported Crypto & Key Management

The package utilizes robust, high-performance cryptographic primitives.

### Cryptographic Standards
- **Signature Scheme:** **EdDSA** is used for digital signatures, specifically over the **BabyJubJub elliptic curve**.
- **Crypto Engine:** Core cryptographic operations (including complex EdDSA verification and advanced hashing) are handled via a **Rust Foreign Function Interface (FFI)** bridge (`affinidi-zkp-crypto-rs`). This ensures optimal performance, memory safety, and reliable integration into Dart/Flutter applications.

## Commitment & Data Integrity

Commitments are the backbone of data integrity, ensuring that the data inputs for the ZK circuit are fixed and verifiable.

### Commitment Generation
The commitment process is highly deterministic:
`commitment = Poseidon([index, encodeString(fieldName), typeTag, encodeValueByType(value)])`

This structure ensures that the commitment binds the field's position (`index`), its name (`fieldName`), its data type (`typeTag`), and its value.

### Data Encoding Types
For commitment determinism, values are strongly typed, and a type tag is included in every commitment calculation:

| Data Type | Type Tag | Description |
| :--- | :--- | :--- |
| `null` | `0` | Null value tag. |
| `bool` | `1` | Boolean value tag. |
| `int`/`BigInt` | `2` | Integer value tag. |
| `String` | `3` | Encoded as raw string bytes. |
| `Map` | `4` | Canonical JSON encoding of the map. |
| `List` | `5` | Canonical JSON encoding of the list. |

### Digest Calculation
The final digest signed by the issuer is calculated by taking a Poseidon hash of the ordered concatenation of all header commitments and payload commitments.

## Signed VC Document Format

The resulting signed document is a structured JSON object that contains all metadata required for verification.

```json
{
  "header": {
    "version": "1",
    "issued_at": 1712345678,
    "expires_at": 1743881678,
    "issuer": "did:example:issuer OR Ax,Ay as decimal or 0x hex pair",
    "holderAx": "decimal_or_0xhex_BabyJub_x",
    "holderAy": "decimal_or_0xhex_BabyJub_y",
    "schema": "0xabcd...hash_of_schema"
  },
  "disclosures": [
    { "field": "age", "value": 28 },
    { "field": "nationality", "value": "USA" }
  ],
  "header_commitments": ["<poseidon(...)>"],
  "payload_commitments": ["<poseidon(...)>"],
  "signature": {
    "R8": ["0x...", "0x..."],
    "S": "0x..."
  }
}
```

## Requirements

- Dart SDK version ^3.0.0

## Installation

Add the package to your `pubspec.yaml` file:

```yaml
dependencies:
  vc_zkp: ^<version_number>
```

Then run the command below to install the package:

```bash
dart pub get
```

## Usage

### 1. Issuer: Create Signed Document

This function handles the commitment generation, digest calculation, and final EdDSA signing.

```dart
import 'package:vc_zkp/vc_zkp.dart';

// 1. Initialize the Issuer
final issuer = VcIssuer();

// 2. Define Header and Disclosures
final header = <String, Object?>{
  'version': '1',
  'issued_at': 1712345678,
  'expires_at': 1743881678,
  // Issuer ID can be a DID or a raw public key pair (Ax, Ay).
  'issuer': '12345678901234567890...,98765432109876543210...',
  'holderAx': '11111111111111111111...',
  'holderAy': '22222222222222222222...',
  'schema': '0xschema_hash',
};

final disclosures = <Disclosure>[
  const Disclosure(field: 'age', value: 28),
  const Disclosure(field: 'nationality', value: 'USA'),
];

// 3. Generate the signed document
final doc = await issuer.createSignedDocument(
  header: header,
  disclosures: disclosures,
  issuerPrivateKeyHex: 'YOUR_64_HEX_PRIVATE_KEY',
);
```

### 2. Holder: Prepare Inputs for Circuit

The holder extracts the necessary commitment components to generate the flat witness map required by the ZKP prover.

```dart
final holder = VcHolder();
final inputs = await holder.prepareForCircuit(doc);

final witnessInputs = inputs.toJson();
// This resulting map contains:
// header_commitments, payload_commitments, final_array, signature,
// holderAx, holderAy, etc.
```

### 3. Holder: Sign Precomputed Digest

The holder can sign the digest using their own private key if required by the workflow.

```dart
final holder = VcHolder();

final signature = await holder.signPreparedDigest(
  digest: 'POSEIDON_DIGEST_AS_DECIMAL_STRING', // Must match the digest used by the Issuer
  privateKeyHex: 'YOUR_64_HEX_PRIVATE_KEY',
);
```

### 4. Verifier: Verify Document (Testing/Local Use Only)

Use the verifier for local validation and testing purposes.

```dart
final verifier = VcVerifier();

// Basic verification of the full document signature and commitments.
final result = await verifier.verifyDocument(doc);

// If advanced DID resolution is available, use the optional overloads:
final resultWithKey = await verifier.verifyDocument(
  doc,
  issuerPublicKeyAx: resolvedAxDecimal,
  issuerPublicKeyAy: resolvedAyDecimal,
);
```

## Testing & Native Symbols

This project includes two test suites:

- **Unit tests:** Run with mocked crypto bridges.
- **Integration tests:** Utilize the real Rust FFI bridge for deep cryptographic validation.

Run unit tests:
```bash
dart test
```

Run all tests (unit + integration):
```bash
dart test --run-skipped
```

**Debugging Native Crashes:** If your application crashes within the native Rust code, download the necessary debug symbols for your specific build triple:

```bash
./tool/download_prebuild_symbols.sh --output-dir ./.native-symbols
```

## Support & Feedback

If you encounter any technical issues or have suggestions regarding the protocol or implementation, please don't hesitate to contact us using [this link](https://share.hsforms.com/1i-4HKZRXSsmENzXtPdIG4g8oa2v).

### Reporting Technical Issues
For issues with the codebase, please open a detailed issue on GitHub. Include a title, clear description, and, ideally, an executable code sample demonstrating the failure.

## Contributing

Want to contribute?

Please review our [CONTRIBUTING](CONTRIBUTING.md) guidelines. We welcome contributions to improving the ZK-VC standards and tooling.