@Tags(<String>['integration'])
import 'dart:math';

import 'package:zkp_vc/zkp_vc.dart';
import 'package:zkp_vc/src/commitments.dart';
import 'package:zkp_vc/src/rust_eddsa_helper_ffi.dart';
import 'package:test/test.dart';

String _randomPrivateKeyHex() {
  final random = Random.secure();
  final bytes = List<int>.generate(32, (_) => random.nextInt(256));
  return bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();
}

Map<String, Object?> _header(String issuerCommaSeparated) {
  return <String, Object?>{
    'version': '1',
    'issued_at': 1712345678,
    'expires_at': 1743881678,
    'issuer': issuerCommaSeparated,
    'holderAx': '5299619240641551281634865583518297030282874472190772894086521144482721001553',
    'holderAy': '16950150798460657717958625567821834550301663161624707787222815936182638968203',
    'schema': 'schema-hash-for-tests',
  };
}

void main() {
  group('Rust bridge integration', () {
    late RustEddsaHelperFfi crypto;
    late VcIssuer issuer;
    late VcHolder holder;
    late VcVerifier verifier;

    setUpAll(() {
      // Requires compiled Rust dynamic library.
      crypto = RustEddsaHelperFfi();
      issuer = VcIssuer(crypto: crypto);
      holder = VcHolder(crypto: crypto);
      verifier = VcVerifier(crypto: crypto);
    });

    test('real bridge creates reproducible signature from digest', () async {
      final privateKeyHex = _randomPrivateKeyHex();
      final derived = await crypto.signDigest(
        msgHash: '1',
        privateKeyHex: privateKeyHex,
      );
      final document = await issuer.createSignedDocument(
        header: _header('${derived.ax},${derived.ay}'),
        disclosures: const <Disclosure>[
          Disclosure(field: 'age', value: 28),
          Disclosure(field: 'nationality', value: 'USA'),
        ],
        issuerPrivateKeyHex: privateKeyHex,
      );

      final inputs = await holder.prepareForCircuit(document);
      final digest = await buildDocumentDigest(
        headerCommitments: inputs.headerCommitments,
        payloadCommitments: inputs.payloadCommitments,
        helper: crypto,
      );

      final signatureFromDigest = await crypto.signDigest(
        msgHash: digest,
        privateKeyHex: privateKeyHex,
      );

      expect(document.signature.r8.first, signatureFromDigest.r8x);
      expect(document.signature.r8.last, signatureFromDigest.r8y);
      expect(document.signature.s, signatureFromDigest.s);
    });

    test('verifyDocument succeeds with real rust-backed verification',
        () async {
      final privateKeyHex = _randomPrivateKeyHex();
      final derived = await crypto.signDigest(
        msgHash: '1',
        privateKeyHex: privateKeyHex,
      );
      final document = await issuer.createSignedDocument(
        header: _header('${derived.ax},${derived.ay}'),
        disclosures: const <Disclosure>[
          Disclosure(field: 'age', value: 42),
        ],
        issuerPrivateKeyHex: privateKeyHex,
      );

      final inputs = await holder.prepareForCircuit(document);
      final digest = await buildDocumentDigest(
        headerCommitments: inputs.headerCommitments,
        payloadCommitments: inputs.payloadCommitments,
        helper: crypto,
      );
      final bridgeValid = await crypto.verifyDigestSignature(
        msgHash: digest,
        publicKeyAx: derived.ax,
        publicKeyAy: derived.ay,
        r8x: document.signature.r8.first,
        r8y: document.signature.r8.last,
        s: document.signature.s,
      );
      expect(bridgeValid, isTrue);

      final result = await verifier.verifyDocument(document);

      expect(result.valid, isTrue);
      expect(result.signatureValid, isTrue);
    });
  });
}
