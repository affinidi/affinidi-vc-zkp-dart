import 'commitments.dart';
import 'issuer_public_key_parse.dart';
import 'models.dart';
import 'rust_eddsa_helper_ffi.dart';

/// Circuit-ready inputs derived by holder from signed document.
class HolderCircuitInputs {
  /// Creates holder circuit input bundle.
  const HolderCircuitInputs({
    required this.headerCommitments,
    required this.payloadCommitments,
    required this.signature,
    required this.issuerAx,
    required this.issuerAy,
    required this.holderAx,
    required this.holderAy,
    this.schemaHash,
  });

  /// Header commitments.
  final List<String> headerCommitments;

  /// Payload commitments.
  final List<String> payloadCommitments;

  /// Final commitment array used for digest hash.
  List<String> get finalArray => <String>[
        ...headerCommitments,
        ...payloadCommitments,
      ];

  /// Signature.
  final VcSignature signature;

  /// Issuer BabyJubJub x when `header['issuer']` is comma-separated `Ax,Ay`;
  /// otherwise empty (e.g. DID — supply key to the circuit separately).
  final String issuerAx;

  /// Issuer BabyJubJub y when `header['issuer']` parses as `Ax,Ay`; otherwise empty.
  final String issuerAy;

  /// Holder BabyJubJub public key x-coordinate from header.
  final String holderAx;

  /// Holder BabyJubJub public key y-coordinate from header.
  final String holderAy;

  /// Schema hash from header.
  final String? schemaHash;

  /// Converts to JSON map suitable for Circom witness inputs.
  Map<String, Object?> toJson() => {
        'header_commitments': headerCommitments,
        'payload_commitments': payloadCommitments,
        'final_array': finalArray,
        'signature': signature.toJson(),
        if (issuerAx.isNotEmpty) 'issuerAx': issuerAx,
        if (issuerAy.isNotEmpty) 'issuerAy': issuerAy,
        'holderAx': holderAx,
        'holderAy': holderAy,
        if (schemaHash != null) 'schema': schemaHash,
      };
}

/// Holder helper for preparing circuit inputs and additional signatures.
class VcHolder {
  /// Creates holder helper with optional injected Rust bridge.
  VcHolder({RustEddsaHelperFfi? crypto})
      : _crypto = crypto ?? RustEddsaHelperFfi();

  final RustEddsaHelperFfi _crypto;

  /// Rebuilds header/payload arrays from signed document and prepares circuit inputs.
  Future<HolderCircuitInputs> prepareForCircuit(
    SignedVcDocument document,
  ) async {
    final headerCommitments = await buildHeaderCommitments(
      document.header,
      _crypto,
    );
    final payloadCommitments = await buildPayloadCommitments(
      document.disclosures,
      _crypto,
    );
    final issuerRaw = document.header['issuer']?.toString() ?? '';
    final parsed = tryParseIssuerBabyJubCommaSeparated(issuerRaw);
    final issuerAx = parsed?.ax ?? '';
    final issuerAy = parsed?.ay ?? '';
    final holderAx = document.header['holderAx']?.toString() ?? '';
    final holderAy = document.header['holderAy']?.toString() ?? '';
    final schema = document.header['schema']?.toString();

    return HolderCircuitInputs(
      headerCommitments: headerCommitments,
      payloadCommitments: payloadCommitments,
      signature: document.signature,
      issuerAx: issuerAx,
      issuerAy: issuerAy,
      holderAx: holderAx,
      holderAy: holderAy,
      schemaHash: schema,
    );
  }

  /// Signs an already prepared Poseidon digest (without re-hashing).
  Future<VcSignature> signPreparedDigest({
    required String digest,
    required String privateKeyHex,
  }) async {
    final signed = await _crypto.signDigest(
      msgHash: digest,
      privateKeyHex: privateKeyHex,
    );
    return VcSignature(
      r8: [signed.r8x, signed.r8y],
      s: signed.s,
    );
  }
}
