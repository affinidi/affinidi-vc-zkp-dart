import 'commitments.dart';
import 'models.dart';
import 'rust_eddsa_helper_ffi.dart';

/// Creates and signs untraceable ZK VC documents.
class VcIssuer {
  /// Creates issuer helper with optional injected Rust bridge.
  VcIssuer({RustEddsaHelperFfi? crypto})
      : _crypto = crypto ?? RustEddsaHelperFfi();

  final RustEddsaHelperFfi _crypto;

  /// Creates a signed VC document.
  ///
  /// Required header `issuer` is a single string: comma-separated BabyJubJub
  /// `Ax,Ay` when embedding the signing key in the document, or an opaque id
  /// such as a DID (resolution is outside this library).
  ///
  /// - Header commitments are built in alphabetical header key order.
  /// - Payload commitments are built from disclosures in list order.
  /// - Document digest is `poseidon([...header, ...payload])`.
  /// - Signature uses Rust BabyJubJub EdDSA over pre-hashed digest.
  Future<SignedVcDocument> createSignedDocument({
    required Map<String, Object?> header,
    required List<Disclosure> disclosures,
    required String issuerPrivateKeyHex,
  }) async {
    _validateHeader(header);
    final headerCommitments = await buildHeaderCommitments(header, _crypto);
    final payloadCommitments =
        await buildPayloadCommitments(disclosures, _crypto);
    final digest = await buildDocumentDigest(
      headerCommitments: headerCommitments,
      payloadCommitments: payloadCommitments,
      helper: _crypto,
    );

    final signature = await _crypto.signDigest(
      msgHash: digest,
      privateKeyHex: issuerPrivateKeyHex,
    );

    return SignedVcDocument(
      header: Map<String, Object?>.from(header),
      disclosures: disclosures,
      headerCommitments: headerCommitments,
      payloadCommitments: payloadCommitments,
      signature: VcSignature(
        r8: [signature.r8x, signature.r8y],
        s: signature.s,
      ),
    );
  }

  void _validateHeader(Map<String, Object?> header) {
    const requiredFields = <String>[
      'version',
      'issued_at',
      'expires_at',
      'issuer',
      'holderAx',
      'holderAy',
      'schema',
    ];
    for (final field in requiredFields) {
      if (!header.containsKey(field)) {
        throw ArgumentError('Header is missing required field "$field".');
      }
    }
  }
}
