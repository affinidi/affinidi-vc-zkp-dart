# Untraceable ZK Verifiable Credential (ZK-VC)

## Overview

Reference **Circom** sources for Untraceable-ZK-VC-style proofs (document digest, holder bind,
challenge signature, payload threshold) live in the repository under
**[example/circuits/](../example/circuits/)** (`UZKPVCProof.circom`, `UZKPVCPayloadThreshold.circom`).

**Untraceable ZK VC** is a privacy-preserving Verifiable Credential format designed for use inside ZK circuits — specifically [Circom](https://github.com/iden3/circom). It draws inspiration from [SD-JWT](https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/) (Selective Disclosure JWT) but replaces its cryptographic primitives with ZK-friendly equivalents, and introduces a presentation flow that makes the holder completely untraceable across verifiers.

The core design goals are:

- **ZK-native**: all cryptographic operations use primitives that are efficient inside arithmetic circuits
- **Untraceable**: no identifier, key, or fingerprint of the holder is ever revealed to a verifier
- **Selective disclosure via predicates**: instead of revealing raw claim values, the holder proves boolean statements about them (e.g. *age > 18*, *balance > 10000*)
- **Composable**: credential verification and claim predicate checks are separated into independent circuits, linked by a session-scoped blinding nonce

---

## Cryptographic Primitives

### Poseidon Hash

All commitment and digest operations use the [Poseidon hash function](https://eprint.iacr.org/2019/458.pdf), a ZK-optimised hash designed specifically for use inside arithmetic circuits over prime fields (BN254 in the context of Groth16/Circom).

Compared to SHA-256 or Keccak, Poseidon requires orders of magnitude fewer constraints per hash operation inside a circuit — typically ~240 constraints vs ~25,000+ for SHA-256. This makes it practical to hash many commitments inside a single proof.

### Baby JubJub

[Baby JubJub](https://eips.ethereum.org/EIPS/eip-2494) is a twisted Edwards elliptic curve defined over the BN254 scalar field. It is the standard curve for in-circuit signature verification in the Circom/SnarkJS ecosystem.

Its key properties relevant here:

- Signature verification can be expressed as ~3,000 constraints inside a Circom circuit
- Natively compatible with BN254, so no field mismatch overhead
- Widely supported in Circom libraries (e.g. [circomlib](https://github.com/iden3/circomlib))

### Groth16

Proofs are generated using [Groth16](https://eprint.iacr.org/2016/260.pdf), a succinct non-interactive argument of knowledge (zk-SNARK). A critical property exploited in this design is that **Groth16 proof generation samples fresh randomness on every run** — meaning two proofs generated from identical circuit inputs are computationally indistinguishable. This eliminates proof-level fingerprinting even when the same credential and challenge are reused.

---

## Credential Structure

The holder stores the issued credential in the following JSON format:

```json
{
  "header": {
    "version": "1",
    "issued_at": 1712345678,
    "expires_at": 1743881678,
    "issuer": "Ax,Ay",
    "holderAx": "decimal_or_0xhex_BabyJub_x",
    "holderAy": "decimal_or_0xhex_BabyJub_y",
    "schema": "0xabcd...hash_of_schema"
  },
  "disclosures": [
    { "field": "age",         "value": 28   },
    { "field": "nationality", "value": "USA" }
  ],
  "header_commitments": [
    "<poseidon(index_0,fieldName_0,type_0,value_0)>",
    "<poseidon(index_1,fieldName_1,type_1,value_1)>"
  ],
  "payload_commitments": [
    "<poseidon(index_0,fieldName_0,type_0,value_0)>",
    "<poseidon(index_1,fieldName_1,type_1,value_1)>"
  ],
  "signature": {
    "R8": ["0x...", "0x..."],
    "S":  "0x..."
  }
}
```

### Field Encoding

All field names are encoded as a single BN254 field element by packing their UTF-8 byte representation into a 254-bit integer. Field names up to 31 bytes (sufficient for any reasonable claim name) fit into a single felt without collision risk:

This means `fieldName` is always exactly one circuit signal — no variable-length arrays at the circuit level.

### Commitment Scheme

Each claim is committed as:

```
commitment[i] = Poseidon([
  index,
  encodeString(fieldName),
  typeTag(value),
  encodeTypedValue(value)
])
```

This ensures type integrity (`28` != `"28"` != `"0x1C"`, `false` != `0` != `null`)
and separates the name/value encoding spaces.

The index + type fields are included to keep commitment semantics stable across
different language runtimes and serializers: the same logical VC must always
produce the same commitments, while semantically different claims must never
collapse to the same commitment preimage.

Header commitments use alphabetical header-key order. Payload commitments are
also ordered deterministically by payload field name before indexes are
assigned. Duplicate payload field names are rejected.

No per-commitment salt is required because the full commitment array is always kept private — it never appears as a public circuit output.

### Digest and Signature

The issuer signs over a flat combined array of all commitments (header first, then payload), producing a single Poseidon digest:

```
combined[0..N+M-1] = [...header_commitments, ...payload_commitments]
digest             = Poseidon(combined)
signature          = BabyJubJub.sign(digest, issuer_privkey)
```

Using a flat array instead of a two-level Merkle structure (header root → payload root → final digest) saves 2–3 Poseidon hash operations inside the circuit, reducing constraint count with no security tradeoff.

---

## Presentation Protocol

### Roles

- **Issuer** — issues and signs the credential
- **Holder** — stores the credential and generates ZK proofs
- **Verifier** — sends a challenge and verifies proofs

### Flow

```
1. Verifier → Holder:   challenge  (random nonce, per-session)

2. Holder:
     - Generates session nonce (random felt)
     - Signs challenge with holder_privkey (Baby JubJub)
     - Constructs Circuit 1 inputs
     - Generates Proof 1

3. Holder → Verifier:   Proof 1 + public signals

4. For each claim predicate:
     - Holder constructs Circuit 2 inputs (reusing session nonce)
     - Generates Proof 2
     - Holder → Verifier: Proof 2 + public signals

5. Verifier:
     - Verifies Proof 1
     - Verifies each Proof 2
     - Confirms blinded_root and nonce match across all proofs
```

---

## Circuit Architecture

### Circuit 1 — Identity and VC Validation

Proves: *"I control the identity to whom this credential was issued, and it was signed by the claimed issuer."*

```
Public inputs:
  issuer_pubkey     — Baby JubJub (Ax, Ay) of the issuer
  challengeDigest   — verifier challenge digest signed by holder
  blinder_factor    — session blinding factor (public for cross-proof binding)
[output]: 
  blinded_root      — Poseidon([digest, blinder_factor])

Private inputs:
  header_commitments []  — array of header commitments
  payload_commitments[]  — array of payload commitments
  doc_signature          — Baby JubJub (R8, S) over digest
  challenge_sig          — Baby JubJub (R8, S) over challenge
  holder_pubkey          — Baby JubJub (Ax, Ay) of the holder
```

Circuit constraints:

```
combined = [...header_commitments, ...payload_commitments]
a) BabyJubJub.verify(challengeDigest, challenge_sig, holder_pubkey)
b) header_commitments[holder_idx] ==
      Poseidon([holder_idx, "holderAx", 2, holder_pubkey.Ax])
   header_commitments[holder_idx+1] ==
      Poseidon([holder_idx+1, "holderAy", 2, holder_pubkey.Ay])
c) digest = Poseidon(combined)
   BabyJubJub.verify(digest, doc_signature, issuer_pubkey)
d) blinded_root == Poseidon([digest, nonce])
```

**The holder's public key never appears in public signals.** The verifier learns nothing about the holder's identity.

### Circuit 2 — Claim Predicate

Proves: *"A specific claim inside the signed credential satisfies predicate P."*

```
Public inputs:
  fieldName         — claim field name to evaluate
  blinder_factor    — must match Circuit 1
  min_threshold     — predicate parameter (e.g. 10000)
[output]:
  blinded_root      — must match Circuit 1

Private inputs:
  header_commitments []  — array of header commitments
  payload_commitments[]  — array of payload commitments
  payloadIndex       — selected payload slot index
  fieldValue         — raw claim value
```

Circuit constraints:

```
combined = [...header_commitments, ...payload_commitments]
a) digest = Poseidon(combined)
   blinded_root == Poseidon([digest, blinder_factor])

b) compute claimed = Poseidon([payloadIndex, fieldName, typeTag(fieldValue), fieldValue])
   and enforce claimed == payload_commitments[payloadIndex] via one-hot index selector

c) enforce `fieldValue` and `min_threshold` in [0, 2^252) via Num2Bits(252),
   then satisfies == GreaterThan(252)([fieldValue, min_threshold])
```

The verifier learns only that *some* claim in the signed document satisfies the threshold, not the value.

---

## Untraceability Properties

| Observable | Verifier sees | Linkable across sessions? |
|---|---|---|
| `holder_pubkey` | Never (private input) | No |
| Raw claim values | Never (private input) | No |
| `blinded_root` | Yes — but randomised by nonce | No |
| `nonce` | Yes — but fresh per session | No |
| `challenge` | Yes — but verifier-generated ephemeral | No |
| `issuer_pubkey` | Yes — public knowledge | Issuer-level only |
| ZK proof bytes | Yes — but Groth16 randomises per run | No |

Even if two verifiers collude and share all observed signals, they cannot correlate any two presentations from the same holder.

---

## Performance Notes

### Constraint Budget (approximate, BN254 / Circom)

| Operation | Constraints |
|---|---|
| Poseidon(2 inputs) | ~240 |
| Poseidon(N inputs) | ~240 + 60×N |
| Baby JubJub verify | ~3,000 |
| GreaterThan(32) | ~64 |
| IsEqual | ~2 |

**Circuit 1** with N=10 total commitments, 2 signature verifications:

```
~2 × 3,000  (challenge sig + doc sig verification)
+ 240 + 60×10  (flat Poseidon digest)
+ 240          (blinded root)
≈ 7,280 constraints
```

**Circuit 2** with N=10 commitments, one predicate:

```
~240 + 60×10   (recompute digest)
+ 240          (blinded root)
+ 240          (recompute commitment)
+ 64           (GreaterThan)
≈ 1,384 constraints
```

These are small circuits by Groth16 standards. Proof generation on a modern laptop or mobile devices takes under 1 second for each. The trusted setup (Powers of Tau) required is minimal — well within the range of existing public ceremonies (e.g. Hermez, Zcash).

---

## Comparison with SD-JWT

| Property | SD-JWT | Untraceable ZK VC |
|---|---|---|
| Selective disclosure | Reveal raw field values | Prove predicates only — no value revealed |
| Holder binding | Holder key in JWT header (visible) | Holder key always private |
| Hash function | SHA-256 | Poseidon (ZK-native) |
| Signature scheme | ECDSA / EdDSA (standard curves) | Baby JubJub (circuit-verifiable) |
| In-circuit verification | Not possible | Native — designed for it |
| Cross-verifier linkability | Via holder key / disclosed values | None |
| Proof randomness | Deterministic presentation | Groth16 randomises every proof |

---

## Standards and Prior Art

This design builds on established, audited primitives and well-known patterns in the ZK identity space:

- **Poseidon hash** — [USENIX Security 2021](https://eprint.iacr.org/2019/458.pdf), used in Semaphore, Polygon ID, Mina Protocol, and Zcash (Orchard PRFs)
- **Baby JubJub** — [EIP-2494](https://eips.ethereum.org/EIPS/eip-2494), standard curve in Ethereum ZK identity stack
- **Groth16** — [Eurocrypt 2016](https://eprint.iacr.org/2016/260.pdf), most widely deployed zk-SNARK
- **circomlib** — reference implementations of all above primitives for Circom
- **SD-JWT** — [IETF draft](https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/), structural inspiration for commitment-based selective disclosure
- **Polygon ID** — prior art for Baby JubJub based VC systems (this design differs by removing all public key exposure from the presentation layer)
