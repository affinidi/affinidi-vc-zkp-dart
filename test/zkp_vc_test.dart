import 'dart:convert';
import 'dart:math';

import 'package:test/test.dart';
import 'package:zkp_vc/src/rust_eddsa_helper_ffi.dart';
import 'package:zkp_vc/zkp_vc.dart';

class _FakeRustEddsaHelper implements RustEddsaHelperFfi {
  final List<List<String>> fieldHashCalls = <List<String>>[];
  final List<List<int>> bitHashCalls = <List<int>>[];
  final List<Map<String, String>> signCalls = <Map<String, String>>[];

  @override
  Future<String> poseidonHashFieldElements(List<String> inputs) async {
    fieldHashCalls.add(List<String>.from(inputs));
    return 'hash:${inputs.join('|')}';
  }

  @override
  Future<String> poseidonHashBits(List<int> bits) async {
    bitHashCalls.add(List<int>.from(bits));
    // Must be decimal string because commitments parser uses BigInt.parse.
    return '123456789';
  }

  @override
  Future<EddsaSignatureResult> signDigest({
    required String msgHash,
    required String privateKeyHex,
  }) async {
    signCalls.add(<String, String>{
      'msgHash': msgHash,
      'privateKeyHex': privateKeyHex,
    });
    return EddsaSignatureResult(
      ax: '123',
      ay: '456',
      r8x: 'r8x:$msgHash',
      r8y: 'r8y:$privateKeyHex',
      s: 's:$msgHash',
    );
  }

  @override
  Future<bool> verifyDigestSignature({
    required String msgHash,
    required String publicKeyAx,
    required String publicKeyAy,
    required String r8x,
    required String r8y,
    required String s,
  }) async {
    return publicKeyAx == '123' &&
        publicKeyAy == '456' &&
        r8x == 'r8x:$msgHash' &&
        s == 's:$msgHash';
  }
}

Map<String, Object?> _buildHeader({
  String schema = 'schema-v1',
  String issuer = '123,456',
}) {
  return <String, Object?>{
    'holderAx': 'holder-ax',
    'holderAy': 'holder-ay',
    'version': '1',
    'issued_at': 1712345678,
    'schema': schema,
    'expires_at': 1743881678,
    'issuer': issuer,
  };
}

String _inlineFelt(String value) {
  final bytes = utf8.encode(value);
  final hex =
      bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();
  return BigInt.parse('0x$hex').toString();
}

String _randomPrivateKeyHex() {
  final random = Random.secure();
  final bytes = List<int>.generate(32, (_) => random.nextInt(256));
  return bytes.map((byte) => byte.toRadixString(16).padLeft(2, '0')).join();
}

void main() {
  group('tryParseIssuerBabyJubCommaSeparated', () {
    test('parses comma-separated pair', () {
      final parsed = tryParseIssuerBabyJubCommaSeparated(' 1 , 2 ');
      expect(parsed?.ax, '1');
      expect(parsed?.ay, '2');
    });

    test('returns null for DID-like issuer string', () {
      expect(tryParseIssuerBabyJubCommaSeparated('did:example:123'), isNull);
    });
  });

  group('VcIssuer', () {
    test('builds header commitments in alphabetical key order', () async {
      final crypto = _FakeRustEddsaHelper();
      final issuer = VcIssuer(crypto: crypto);

      final document = await issuer.createSignedDocument(
        header: _buildHeader(),
        disclosures: const <Disclosure>[
          Disclosure(field: 'age', value: 28),
        ],
        issuerPrivateKeyHex: _randomPrivateKeyHex(),
      );

      expect(document.headerCommitments, hasLength(7));
      final sortedHeaderKeys = <String>[
        'expires_at',
        'holderAx',
        'holderAy',
        'issued_at',
        'issuer',
        'schema',
        'version',
      ];
      for (var index = 0; index < sortedHeaderKeys.length; index += 1) {
        expect(
          crypto.fieldHashCalls[index].first,
          equals(_inlineFelt(sortedHeaderKeys[index])),
        );
      }
    });

    test('uses poseidon bits for long string conversion', () async {
      final crypto = _FakeRustEddsaHelper();
      final issuer = VcIssuer(crypto: crypto);
      final longString = 'this-is-a-very-long-string-over-thirty-one-bytes';

      await issuer.createSignedDocument(
        header: _buildHeader(schema: longString),
        disclosures: const <Disclosure>[
          Disclosure(field: 'nationality', value: 'USA'),
        ],
        issuerPrivateKeyHex: _randomPrivateKeyHex(),
      );

      expect(crypto.bitHashCalls, isNotEmpty);
    });
  });

  group('VcHolder', () {
    test('reuses commitments from document when present', () async {
      final crypto = _FakeRustEddsaHelper();
      final holder = VcHolder(crypto: crypto);
      final document = SignedVcDocument(
        header: _buildHeader(),
        disclosures: const <Disclosure>[
          Disclosure(field: 'age', value: 28),
        ],
        headerCommitments: const <String>['h1', 'h2'],
        payloadCommitments: const <String>['p1'],
        signature: const VcSignature(r8: <String>['r8x', 'r8y'], s: 's'),
      );

      final inputs = await holder.prepareForCircuit(document);

      expect(inputs.headerCommitments, equals(const <String>['h1', 'h2']));
      expect(inputs.payloadCommitments, equals(const <String>['p1']));
      expect(inputs.finalArray, equals(const <String>['h1', 'h2', 'p1']));
      expect(inputs.issuerAx, '123');
      expect(inputs.issuerAy, '456');
      expect(inputs.holderAx, 'holder-ax');
      expect(inputs.holderAy, 'holder-ay');
      final witness = inputs.toJson();
      expect(witness['issuerAx'], '123');
      expect(witness['issuerAy'], '456');
      expect(witness['holderAx'], 'holder-ax');
      expect(witness['holderAy'], 'holder-ay');
      expect(crypto.fieldHashCalls, isEmpty);
    });

    test('rebuilds commitments if missing in json document', () async {
      final crypto = _FakeRustEddsaHelper();
      final holder = VcHolder(crypto: crypto);
      final document = SignedVcDocument.fromJson(<String, dynamic>{
        'header': <String, dynamic>{
          'version': '1',
          'issuer': 'issuer-ax,issuer-ay',
          'holderAx': 'holder-ax',
          'holderAy': 'holder-ay',
        },
        'disclosures': <Map<String, Object?>>[
          <String, Object?>{'field': 'age', 'value': 18},
        ],
        'signature': <String, Object?>{
          'R8': <String>['r8x', 'r8y'],
          'S': 's',
        },
      });

      final inputs = await holder.prepareForCircuit(document);

      expect(inputs.headerCommitments, isNotEmpty);
      expect(inputs.payloadCommitments, isNotEmpty);
      expect(inputs.schemaHash, isNull);
      expect(crypto.fieldHashCalls, isNotEmpty);
    });
  });

  group('VcVerifier', () {
    test('verifies document using internal signature verification', () async {
      final crypto = _FakeRustEddsaHelper();
      final issuer = VcIssuer(crypto: crypto);
      final verifier = VcVerifier(crypto: crypto);

      final document = await issuer.createSignedDocument(
        header: _buildHeader(),
        disclosures: const <Disclosure>[
          Disclosure(field: 'age', value: 28),
        ],
        issuerPrivateKeyHex: _randomPrivateKeyHex(),
      );

      final result = await verifier.verifyDocument(document);

      expect(result.valid, isTrue);
      expect(result.signatureValid, isTrue);
      expect(result.toJson().containsKey('circuit_inputs'), isFalse);
    });

    test('returns invalid when signature is tampered', () async {
      final crypto = _FakeRustEddsaHelper();
      final issuer = VcIssuer(crypto: crypto);
      final verifier = VcVerifier(crypto: crypto);

      final document = await issuer.createSignedDocument(
        header: _buildHeader(),
        disclosures: const <Disclosure>[
          Disclosure(field: 'nationality', value: 'USA'),
        ],
        issuerPrivateKeyHex: _randomPrivateKeyHex(),
      );

      final tampered = SignedVcDocument(
        header: document.header,
        disclosures: document.disclosures,
        headerCommitments: document.headerCommitments,
        payloadCommitments: document.payloadCommitments,
        signature: const VcSignature(
          r8: <String>['tampered-r8x', 'tampered-r8y'],
          s: 'tampered-s',
        ),
      );

      final result = await verifier.verifyDocument(tampered);

      expect(result.valid, isFalse);
      expect(result.signatureValid, isFalse);
      expect(result.error, contains('Signature verification failed'));
    });

    test('DID issuer needs explicit public key for verification', () async {
      final crypto = _FakeRustEddsaHelper();
      final issuer = VcIssuer(crypto: crypto);
      final verifier = VcVerifier(crypto: crypto);

      final document = await issuer.createSignedDocument(
        header: _buildHeader(issuer: 'did:example:issuer'),
        disclosures: const <Disclosure>[
          Disclosure(field: 'age', value: 28),
        ],
        issuerPrivateKeyHex: _randomPrivateKeyHex(),
      );

      final withoutKey = await verifier.verifyDocument(document);
      expect(withoutKey.valid, isFalse);
      expect(withoutKey.error, contains('Issuer signing key'));

      final withKey = await verifier.verifyDocument(
        document,
        issuerPublicKeyAx: '123',
        issuerPublicKeyAy: '456',
      );
      expect(withKey.valid, isTrue);
      expect(withKey.signatureValid, isTrue);
    });
  });
}
