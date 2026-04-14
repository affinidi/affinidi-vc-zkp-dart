import 'commitments.dart';
import 'holder.dart';
import 'issuer_public_key_parse.dart';
import 'models.dart';
import 'rust_eddsa_helper_ffi.dart';

/// Verification result with details.
class VerificationResult {
  /// Creates a verification result.
  const VerificationResult({
    required this.valid,
    this.error,
    this.signatureValid = false,
  });

  /// Overall validity.
  final bool valid;

  /// Error reason when invalid.
  final String? error;

  /// Signature verification result.
  final bool signatureValid;

  /// Converts result to JSON map.
  Map<String, Object?> toJson() => {
        'valid': valid,
        'error': error,
        'signature_valid': signatureValid,
      };
}

/// Document verifier intended for tests and local debugging.
///
/// In production untraceable VC flows, verifiers usually receive only a ZKP
/// presentation and verify that proof, not the full signed document.
class VcVerifier {
  /// Creates verifier helper with optional Rust bridge.
  VcVerifier({RustEddsaHelperFfi? crypto}) {
    final helper = crypto ?? RustEddsaHelperFfi();
    _crypto = helper;
    _holder = VcHolder(crypto: helper);
  }

  late final RustEddsaHelperFfi _crypto;
  late final VcHolder _holder;

  /// Verifies a signed VC document.
  ///
  /// When [issuerPublicKeyAx] and [issuerPublicKeyAy] are set, they are used
  /// for EdDSA (for example after resolving a DID outside this library).
  /// Otherwise, if `header['issuer']` is comma-separated `Ax,Ay`, that pair is
  /// used. If neither applies, verification fails with a clear error.
  Future<VerificationResult> verifyDocument(
    SignedVcDocument document, {
    String? issuerPublicKeyAx,
    String? issuerPublicKeyAy,
  }) async {
    try {
      final circuitInputs = await _holder.prepareForCircuit(document);

      if (document.headerCommitments.isNotEmpty &&
          !_sameList(
            circuitInputs.headerCommitments,
            document.headerCommitments,
          )) {
        return const VerificationResult(
          valid: false,
          error: 'Header commitments mismatch.',
        );
      }
      if (document.payloadCommitments.isNotEmpty &&
          !_sameList(
            circuitInputs.payloadCommitments,
            document.payloadCommitments,
          )) {
        return const VerificationResult(
          valid: false,
          error: 'Payload commitments mismatch.',
        );
      }

      final issuerPublicKey = _resolveIssuerPublicKey(
        document.header,
        issuerPublicKeyAx: issuerPublicKeyAx,
        issuerPublicKeyAy: issuerPublicKeyAy,
      );
      final digest = await buildDocumentDigest(
        headerCommitments: circuitInputs.headerCommitments,
        payloadCommitments: circuitInputs.payloadCommitments,
        helper: _crypto,
      );
      final signatureValid = await _crypto.verifyDigestSignature(
        msgHash: digest,
        publicKeyAx: issuerPublicKey.ax,
        publicKeyAy: issuerPublicKey.ay,
        r8x: _normalizeFieldNumber(document.signature.r8.first),
        r8y: _normalizeFieldNumber(document.signature.r8.last),
        s: _normalizeFieldNumber(document.signature.s),
      );
      if (!signatureValid) {
        return const VerificationResult(
          valid: false,
          error: 'Signature verification failed.',
          signatureValid: false,
        );
      }

      return const VerificationResult(
        valid: true,
        signatureValid: true,
      );
    } on Object catch (error) {
      return VerificationResult(
        valid: false,
        error: 'Verification failed: $error',
      );
    }
  }

  bool _sameList(List<String> left, List<String> right) {
    if (left.length != right.length) {
      return false;
    }
    for (var index = 0; index < left.length; index += 1) {
      if (left[index] != right[index]) {
        return false;
      }
    }
    return true;
  }

  _IssuerPublicKey _resolveIssuerPublicKey(
    Map<String, Object?> header, {
    String? issuerPublicKeyAx,
    String? issuerPublicKeyAy,
  }) {
    final overrideAx = issuerPublicKeyAx?.trim() ?? '';
    final overrideAy = issuerPublicKeyAy?.trim() ?? '';
    if (overrideAx.isNotEmpty && overrideAy.isNotEmpty) {
      return _IssuerPublicKey(
        ax: _normalizeFieldNumber(overrideAx),
        ay: _normalizeFieldNumber(overrideAy),
      );
    }
    final parsed = tryParseIssuerBabyJubCommaSeparated(
      header['issuer']?.toString(),
    );
    if (parsed != null) {
      return _IssuerPublicKey(ax: parsed.ax, ay: parsed.ay);
    }
    throw const FormatException(
      'Issuer signing key: set issuerPublicKeyAx and issuerPublicKeyAy, '
      'or use header issuer as comma-separated Ax,Ay.',
    );
  }

  String _normalizeFieldNumber(String value) {
    final trimmed = value.trim();
    if (trimmed.startsWith('0x') || trimmed.startsWith('0X')) {
      return BigInt.parse(trimmed).toString();
    }
    return trimmed;
  }
}

class _IssuerPublicKey {
  const _IssuerPublicKey({
    required this.ax,
    required this.ay,
  });

  final String ax;
  final String ay;
}
