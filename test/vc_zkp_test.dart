import 'dart:convert';
import 'dart:math';

import 'package:test/test.dart';
import 'package:vc_zkp/src/commitments.dart';
import 'package:vc_zkp/vc_zkp.dart';

class _FakeRustEddsaHelper implements RustEddsaHelperFfi {
  final List<List<String>> fieldHashCalls = <List<String>>[];
  final List<List<int>> bitHashCalls = <List<int>>[];
  final List<Map<String, String>> signCalls = <Map<String, String>>[];
  final List<String> deriveCalls = <String>[];

  @override
  Future<String> poseidonHashFieldElements(List<String> inputs) async {
    fieldHashCalls.add(List<String>.from(inputs));
    var acc = BigInt.zero;
    for (final input in inputs) {
      for (final unit in input.codeUnits) {
        acc = (acc * BigInt.from(257) + BigInt.from(unit)) %
            BigInt.parse(
              '21888242871839275222246405745257275088548364400416034343698204186575808495617',
            );
      }
      acc = (acc + BigInt.from(17)) %
          BigInt.parse(
            '21888242871839275222246405745257275088548364400416034343698204186575808495617',
          );
    }
    return acc.toString();
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
  Future<EddsaPublicKeyResult> derivePublicKey({
    required String privateKeyHex,
  }) async {
    deriveCalls.add(privateKeyHex);
    return const EddsaPublicKeyResult(ax: '123', ay: '456');
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
    'holderAx': '789',
    'holderAy': '987',
    'version': '1',
    'issued_at': 1700000000,
    'schema': schema,
    'expires_at': 1900000000,
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

  group('VcKeyDerivation', () {
    test('derives public key coordinates from private key hex', () async {
      final crypto = _FakeRustEddsaHelper();
      final keyDerivation = VcKeyDerivation(crypto: crypto);

      final result = await keyDerivation.derivePublicKey(
        privateKeyHex: _randomPrivateKeyHex(),
      );

      expect(result.ax, '123');
      expect(result.ay, '456');
      expect(result.asCommaSeparated(), '123,456');
      expect(crypto.deriveCalls, hasLength(1));
      expect(crypto.signCalls, isEmpty);
    });
  });

  group('VcIssuer', () {
    test('builds header commitments in alphabetical key order with indexes',
        () async {
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
        final commitmentCall = crypto.fieldHashCalls[index];
        expect(commitmentCall.first, equals(index.toString()));
        expect(commitmentCall[1], equals(_inlineFelt(sortedHeaderKeys[index])));
        expect(commitmentCall[2], isIn(<String>['0', '1', '2', '3', '4', '5']));
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

  group('buildDocumentDigest', () {
    test('rejects single-element commitment array for domain separation',
        () async {
      final crypto = _FakeRustEddsaHelper();

      expect(
        () => buildDocumentDigest(
          headerCommitments: const <String>['only-one'],
          payloadCommitments: const <String>[],
          helper: crypto,
        ),
        throwsA(
          isA<ArgumentError>().having(
            (error) => error.message,
            'message',
            contains('single element'),
          ),
        ),
      );
    });

    test('field commitments distinguish numeric and string values', () async {
      final crypto = _FakeRustEddsaHelper();
      final intCommitment = await buildFieldCommitment(
        index: 0,
        fieldName: 'age',
        value: 28,
        helper: crypto,
      );
      final stringCommitment = await buildFieldCommitment(
        index: 0,
        fieldName: 'age',
        value: '28',
        helper: crypto,
      );
      final hexStringCommitment = await buildFieldCommitment(
        index: 0,
        fieldName: 'age',
        value: '0x1C',
        helper: crypto,
      );

      expect(intCommitment, isNot(equals(stringCommitment)));
      expect(stringCommitment, isNot(equals(hexStringCommitment)));
      expect(intCommitment, isNot(equals(hexStringCommitment)));
    });

    test('field commitments distinguish null, bool, int and string zero', () async {
      final crypto = _FakeRustEddsaHelper();
      final cNull = await buildFieldCommitment(
        index: 0,
        fieldName: 'verified',
        value: null,
        helper: crypto,
      );
      final cBool = await buildFieldCommitment(
        index: 0,
        fieldName: 'verified',
        value: false,
        helper: crypto,
      );
      final cInt = await buildFieldCommitment(
        index: 0,
        fieldName: 'verified',
        value: 0,
        helper: crypto,
      );
      final cString = await buildFieldCommitment(
        index: 0,
        fieldName: 'verified',
        value: '0',
        helper: crypto,
      );

      expect(cNull, isNot(equals(cBool)));
      expect(cNull, isNot(equals(cInt)));
      expect(cNull, isNot(equals(cString)));
      expect(cBool, isNot(equals(cInt)));
      expect(cBool, isNot(equals(cString)));
      expect(cInt, isNot(equals(cString)));
    });

    test('payload commitments reject reserved disclosure field names', () async {
      final crypto = _FakeRustEddsaHelper();
      expect(
        () => buildPayloadCommitments(
          const <Disclosure>[
            Disclosure(field: 'holderAx', value: '123'),
          ],
          crypto,
        ),
        throwsA(
          isA<ArgumentError>().having(
            (error) => error.message,
            'message',
            contains('reserved for header use'),
          ),
        ),
      );
    });

    test('payload commitments are deterministic regardless of input order',
        () async {
      final crypto = _FakeRustEddsaHelper();
      final first = await buildPayloadCommitments(
        const <Disclosure>[
          Disclosure(field: 'zField', value: 1),
          Disclosure(field: 'aField', value: 2),
        ],
        crypto,
      );
      final second = await buildPayloadCommitments(
        const <Disclosure>[
          Disclosure(field: 'aField', value: 2),
          Disclosure(field: 'zField', value: 1),
        ],
        crypto,
      );

      expect(first, equals(second));
    });

    test('payload commitments reject duplicate field names', () async {
      final crypto = _FakeRustEddsaHelper();
      expect(
        () => buildPayloadCommitments(
          const <Disclosure>[
            Disclosure(field: 'age', value: 18),
            Disclosure(field: 'age', value: 19),
          ],
          crypto,
        ),
        throwsA(
          isA<ArgumentError>().having(
            (error) => error.message,
            'message',
            contains('Duplicate payload field'),
          ),
        ),
      );
    });
  });

  group('VcHolder', () {
    test('always rebuilds commitments from document payload', () async {
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

      expect(inputs.headerCommitments, isNot(equals(const <String>['h1', 'h2'])));
      expect(inputs.payloadCommitments, isNot(equals(const <String>['p1'])));
      expect(inputs.finalArray, isNot(equals(const <String>['h1', 'h2', 'p1'])));
      expect(inputs.issuerAx, '123');
      expect(inputs.issuerAy, '456');
      expect(inputs.holderAx, '789');
      expect(inputs.holderAy, '987');
      final witness = inputs.toJson();
      expect(witness['issuerAx'], '123');
      expect(witness['issuerAy'], '456');
      expect(witness['holderAx'], '789');
      expect(witness['holderAy'], '987');
      expect(crypto.fieldHashCalls, isNotEmpty);
    });

    test('rebuilds commitments if missing in json document', () async {
      final crypto = _FakeRustEddsaHelper();
      final holder = VcHolder(crypto: crypto);
      final document = SignedVcDocument.fromJson(<String, dynamic>{
        'header': <String, dynamic>{
          'version': '1',
          'issuer': 'issuer-ax,issuer-ay',
          'holderAx': '789',
          'holderAy': '987',
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

      final result = await verifier.verifyDocument(
        document,
        issuerPublicKeyAx: '123',
        issuerPublicKeyAy: '456',
      );

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

      final result = await verifier.verifyDocument(
        tampered,
        issuerPublicKeyAx: '123',
        issuerPublicKeyAy: '456',
      );

      expect(result.valid, isFalse);
      expect(result.signatureValid, isFalse);
      expect(result.error, contains('Signature verification failed'));
    });

    test('DID issuer with explicit key fails unless app-match is pre-verified',
        () async {
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

      final withoutBypass = await verifier.verifyDocument(
        document,
        issuerPublicKeyAx: '123',
        issuerPublicKeyAy: '456',
      );
      expect(withoutBypass.valid, isFalse);
      expect(
        withoutBypass.error,
        contains('could not be derived from header issuer for matching'),
      );

      final withBypass = await verifier.verifyDocument(
        document,
        issuerPublicKeyAx: '123',
        issuerPublicKeyAy: '456',
        isIssuerPubKeyMatchAlreadyVerified: true,
      );
      expect(withBypass.valid, isTrue);
      expect(withBypass.signatureValid, isTrue);
    });

    test('can skip issuer header/key match when already verified by app', () async {
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

      final skipped = await verifier.verifyDocument(
        document,
        issuerPublicKeyAx: '999',
        issuerPublicKeyAy: '888',
        isIssuerPubKeyMatchAlreadyVerified: true,
      );
      expect(skipped.valid, isFalse);
      expect(skipped.error, contains('Signature verification failed'));
    });

    test('fails when provided key mismatches parseable issuer header', () async {
      final crypto = _FakeRustEddsaHelper();
      final issuer = VcIssuer(crypto: crypto);
      final verifier = VcVerifier(crypto: crypto);

      final document = await issuer.createSignedDocument(
        header: _buildHeader(issuer: '123,456'),
        disclosures: const <Disclosure>[
          Disclosure(field: 'age', value: 28),
        ],
        issuerPrivateKeyHex: _randomPrivateKeyHex(),
      );

      final result = await verifier.verifyDocument(
        document,
        issuerPublicKeyAx: '111',
        issuerPublicKeyAy: '222',
      );
      expect(result.valid, isFalse);
      expect(result.error, contains('Issuer signing key mismatch'));
    });

    test('rejects expired credential before checking commitments', () async {
      final crypto = _FakeRustEddsaHelper();
      final issuer = VcIssuer(crypto: crypto);
      final verifier = VcVerifier(crypto: crypto);

      final expiredHeader = <String, Object?>{
        ..._buildHeader(),
        'issued_at': 1000000000,
        'expires_at': 1100000000,
      };
      final document = await issuer.createSignedDocument(
        header: expiredHeader,
        disclosures: const <Disclosure>[Disclosure(field: 'age', value: 28)],
        issuerPrivateKeyHex: _randomPrivateKeyHex(),
      );

      final result = await verifier.verifyDocument(
        document,
        issuerPublicKeyAx: '123',
        issuerPublicKeyAy: '456',
      );
      expect(result.valid, isFalse);
      expect(result.error, contains('expired'));
    });

    test('rejects credential whose issued_at is in the future', () async {
      final crypto = _FakeRustEddsaHelper();
      final issuer = VcIssuer(crypto: crypto);
      final verifier = VcVerifier(crypto: crypto);

      final futureHeader = <String, Object?>{
        ..._buildHeader(),
        'issued_at': 9999999999,
        'expires_at': 9999999999 + 86400,
      };
      final document = await issuer.createSignedDocument(
        header: futureHeader,
        disclosures: const <Disclosure>[Disclosure(field: 'age', value: 28)],
        issuerPrivateKeyHex: _randomPrivateKeyHex(),
      );

      final result = await verifier.verifyDocument(
        document,
        issuerPublicKeyAx: '123',
        issuerPublicKeyAy: '456',
      );
      expect(result.valid, isFalse);
      expect(result.error, contains('not yet valid'));
    });

    test('rejects credential with missing expires_at', () async {
      final crypto = _FakeRustEddsaHelper();
      final issuer = VcIssuer(crypto: crypto);
      final verifier = VcVerifier(crypto: crypto);

      // Build a valid document first, then strip expires_at from the header
      // to simulate a malformed document reaching the verifier.
      final valid = await issuer.createSignedDocument(
        header: _buildHeader(),
        disclosures: const <Disclosure>[Disclosure(field: 'age', value: 28)],
        issuerPrivateKeyHex: _randomPrivateKeyHex(),
      );
      final noExpiryHeader = Map<String, Object?>.from(valid.header)
        ..remove('expires_at');
      final document = SignedVcDocument(
        header: noExpiryHeader,
        disclosures: valid.disclosures,
        headerCommitments: valid.headerCommitments,
        payloadCommitments: valid.payloadCommitments,
        signature: valid.signature,
      );

      final result = await verifier.verifyDocument(
        document,
        issuerPublicKeyAx: '123',
        issuerPublicKeyAy: '456',
      );
      expect(result.valid, isFalse);
      expect(result.error, contains('expires_at'));
    });

    test('fails when visible header is tampered but commitments are reused',
        () async {
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

      final tampered = SignedVcDocument(
        header: <String, Object?>{
          ...document.header,
          'schema': 'attacker-schema',
        },
        disclosures: document.disclosures,
        headerCommitments: document.headerCommitments,
        payloadCommitments: document.payloadCommitments,
        signature: document.signature,
      );

      final result = await verifier.verifyDocument(tampered);
      expect(result.valid, isFalse);
      expect(result.error, contains('Header commitments mismatch'));
    });
  });
}
