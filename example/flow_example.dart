// Run from the repository root (after `cargo build --release` in `lib/rust_eddsa_helper`):
//   dart run example/flow_example.dart
//
// Reference Circom sources for field layout and public signals live under:
//   example/circuits/
//
// For in-app proof generation on mobile, you can combine witness calculation with a
// fast Groth16 prover, for example:
//   - https://github.com/iden3/flutter-rapidsnark — Flutter wrapper around rapidsnark
//   - https://github.com/iden3/circom-witnesscalc — witness calculator (CVM / native)
//   - https://github.com/iden3/rapidsnark — C++ Groth16 prover for circom/snarkjs artifacts
//
// Typical flow: compile circuits → trusted setup → generate witness (circom-witnesscalc
// or WASM calculator) → prove (rapidsnark / snarkjs) → verify off-device or on-chain.

import 'dart:convert';
import 'dart:math';

import 'package:affinidi_untraceable_zk_vc/affinidi_untraceable_zk_vc.dart';
import 'package:affinidi_untraceable_zk_vc/src/rust_eddsa_helper_ffi.dart';

/// BN254 field prime (same as `lib/src/commitments.dart`).
final _bn254Prime = BigInt.parse(
  '21888242871839275222246405745257275088548364400416034343698204186575808495617',
);

String _randomPrivateKeyHex(Random random) {
  return List<int>.generate(32, (_) => random.nextInt(256))
      .map((b) => b.toRadixString(16).padLeft(2, '0'))
      .join();
}

/// Uniform random non-zero field element as a decimal string (for `blinder_factor`).
String _randomBlinderFactor(Random random) {
  while (true) {
    final bytes = List<int>.generate(31, (_) => random.nextInt(256));
    var v = BigInt.zero;
    for (final b in bytes) {
      v = (v << 8) + BigInt.from(b);
    }
    v = v % _bn254Prime;
    if (v > BigInt.zero) {
      return v.toString();
    }
  }
}

Future<void> main() async {
  final random = Random.secure();
  final issuerPrivateKeyHex = _randomPrivateKeyHex(random);
  final holderPrivateKeyHex = _randomPrivateKeyHex(random);
  final blinderFactor = _randomBlinderFactor(random);

  final crypto = RustEddsaHelperFfi();

  // Recover BabyJub coordinates for issuer/holder; the sign API always returns Ax/Ay
  // derived from the private key (see Rust `derive_public_key` in `sign_eddsa`).
  final issuerPub = await crypto.signDigest(
    msgHash: '1',
    privateKeyHex: issuerPrivateKeyHex,
  );
  final holderPub = await crypto.signDigest(
    msgHash: '1',
    privateKeyHex: holderPrivateKeyHex,
  );

  final header = <String, Object?>{
    'version': '1',
    'issued_at': 1712345678,
    'expires_at': 1743881678,
    'issuer': 'did:untraceable:example-issuer',
    'holderAx': holderPub.ax,
    'holderAy': holderPub.ay,
    'schema': 'schema-hash-for-example',
  };

  final disclosures = <Disclosure>[
    const Disclosure(field: 'claim_0', value: 0),
    const Disclosure(field: 'claim_1', value: 1),
    const Disclosure(field: 'claim_2', value: 2),
    const Disclosure(field: 'claim_3', value: 'a'),
    const Disclosure(field: 'claim_4', value: 'b'),
  ];

  final issuer = VcIssuer(crypto: crypto);
  final document = await issuer.createSignedDocument(
    header: header,
    disclosures: disclosures,
    issuerPrivateKeyHex: issuerPrivateKeyHex,
  );

  final holder = VcHolder(crypto: crypto);
  final holderInputs = await holder.prepareForCircuit(document);

  final challengeNonce = List<int>.generate(32, (_) => random.nextInt(256));
  final challengeNonceHex = challengeNonce
      .map((b) => b.toRadixString(16).padLeft(2, '0'))
      .join();
  final challengeNonceBi = BigInt.parse(challengeNonceHex, radix: 16);
  final challengeDigest = await crypto.poseidonHashFieldElements(
    <String>[challengeNonceBi.toString()],
  );

  final challengeSig = await holder.signPreparedDigest(
    digest: challengeDigest,
    privateKeyHex: holderPrivateKeyHex,
  );

  final sig = document.signature;
  final circuitInputs = <String, Object?>{
    'header_commitments': holderInputs.headerCommitments,
    'payload_commitments': holderInputs.payloadCommitments,
    'issuerAx': issuerPub.ax,
    'issuerAy': issuerPub.ay,
    'documentR8x': sig.r8[0],
    'documentR8y': sig.r8[1],
    'documentS': sig.s,
    'holderAx': holderInputs.holderAx,
    'holderAy': holderInputs.holderAy,
    'challengeDigest': challengeDigest,
    'challengeR8x': challengeSig.r8[0],
    'challengeR8y': challengeSig.r8[1],
    'challengeS': challengeSig.s,
    'blinder_factor': blinderFactor,
  };

  final bundle = <String, Object?>{
    'circuitInputs': circuitInputs,
    'disclosures': disclosures.map((d) => d.toJson()).toList(),
    '_exampleOnly': <String, Object?>{
      'note':
          'Secrets for local experimentation only — remove before sharing logs or artifacts.',
      'issuerPrivateKeyHex': issuerPrivateKeyHex,
      'holderPrivateKeyHex': holderPrivateKeyHex,
      'challengeNonceHex': challengeNonceHex,
    },
  };

  // ignore: avoid_print
  print(JsonEncoder.withIndent('  ').convert(bundle));
}
