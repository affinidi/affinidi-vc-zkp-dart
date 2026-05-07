import 'commitments.dart';
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
  }

  late final RustEddsaHelperFfi _crypto;

  /// Verifies a signed VC document.
  ///
  /// [issuerPublicKeyAx] and [issuerPublicKeyAy] must always be provided and
  /// are used for EdDSA when provided (for example after resolving a DID
  /// outside this library).
  ///
  /// By default, the verifier tries to derive issuer key from
  /// `header['issuer']` when it is comma-separated `Ax,Ay`. If
  /// [issuerPublicKeyAx]/[issuerPublicKeyAy] are provided, they must match the
  /// derived key. Set [isIssuerPubKeyMatchAlreadyVerified] to `true` to skip
  /// that issuer header-to-key match.
  Future<VerificationResult> verifyDocument(
    SignedVcDocument document, {
    String? issuerPublicKeyAx,
    String? issuerPublicKeyAy,
    bool isIssuerPubKeyMatchAlreadyVerified = false,
  }) async {
    try {
      final temporalCheck = _checkTemporalValidity(document.header);
      if (temporalCheck != null) {
        return VerificationResult(valid: false, error: temporalCheck);
      }

      final computedHeaderCommitments = await buildHeaderCommitments(
        document.header,
        _crypto,
      );
      final computedPayloadCommitments = await buildPayloadCommitments(
        document.disclosures,
        _crypto,
      );

      if (!_sameList(computedHeaderCommitments, document.headerCommitments)) {
        return const VerificationResult(
          valid: false,
          error: 'Header commitments mismatch.',
        );
      }
      if (!_sameList(computedPayloadCommitments, document.payloadCommitments)) {
        return const VerificationResult(
          valid: false,
          error: 'Payload commitments mismatch.',
        );
      }

      final issuerPublicKey = _resolveIssuerPublicKey(
        document.header,
        issuerPublicKeyAx: issuerPublicKeyAx,
        issuerPublicKeyAy: issuerPublicKeyAy,
        isIssuerPubKeyMatchAlreadyVerified: isIssuerPubKeyMatchAlreadyVerified,
      );
      final digest = await buildDocumentDigest(
        headerCommitments: computedHeaderCommitments,
        payloadCommitments: computedPayloadCommitments,
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

      return const VerificationResult(valid: true, signatureValid: true);
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
    required bool isIssuerPubKeyMatchAlreadyVerified,
  }) {
    final overrideAx = issuerPublicKeyAx?.trim() ?? '';
    final overrideAy = issuerPublicKeyAy?.trim() ?? '';
    final hasOverride = overrideAx.isNotEmpty || overrideAy.isNotEmpty;
    if (hasOverride && (overrideAx.isEmpty || overrideAy.isEmpty)) {
      throw const FormatException(
        'Issuer signing key must include both '
        'issuerPublicKeyAx and issuerPublicKeyAy.',
      );
    }

    final parsed = tryParseIssuerBabyJubCommaSeparated(
      header['issuer']?.toString(),
    );

    if (overrideAx.isNotEmpty && overrideAy.isNotEmpty) {
      final normalizedOverrideAx = _normalizeFieldNumber(overrideAx);
      final normalizedOverrideAy = _normalizeFieldNumber(overrideAy);
      if (!isIssuerPubKeyMatchAlreadyVerified) {
        if (parsed == null) {
          throw const FormatException(
            'Issuer signing key could not be derived from header issuer for '
            'matching. Set isIssuerPubKeyMatchAlreadyVerified: true to skip '
            'this check.',
          );
        }
        if (parsed.ax != normalizedOverrideAx ||
            parsed.ay != normalizedOverrideAy) {
          throw const FormatException(
            'Issuer signing key mismatch: derived key from header issuer does '
            'not match issuerPublicKeyAx/issuerPublicKeyAy.',
          );
        }
      }
      return _IssuerPublicKey(
        ax: normalizedOverrideAx,
        ay: normalizedOverrideAy,
      );
    }

    if (parsed != null) {
      return _IssuerPublicKey(ax: parsed.ax, ay: parsed.ay);
    }

    throw const FormatException(
      'Issuer signing key: provide issuerPublicKeyAx/issuerPublicKeyAy, '
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

  /// Returns an error string when the credential is outside its validity
  /// window, or `null` when the timestamps are present and the credential is
  /// currently valid.
  String? _checkTemporalValidity(Map<String, Object?> header) {
    final issuedAtRaw = header['issued_at'];
    final expiresAtRaw = header['expires_at'];

    final issuedAt = issuedAtRaw is int
        ? issuedAtRaw
        : int.tryParse(issuedAtRaw?.toString() ?? '');
    final expiresAt = expiresAtRaw is int
        ? expiresAtRaw
        : int.tryParse(expiresAtRaw?.toString() ?? '');

    if (issuedAt == null) {
      return 'Credential header is missing a valid issued_at timestamp.';
    }
    if (expiresAt == null) {
      return 'Credential header is missing a valid expires_at timestamp.';
    }

    final nowSeconds = DateTime.now().millisecondsSinceEpoch ~/ 1000;

    if (nowSeconds < issuedAt) {
      return 'Credential is not yet valid (issued_at is in the future).';
    }
    if (nowSeconds > expiresAt) {
      return 'Credential has expired.';
    }
    return null;
  }
}

class _IssuerPublicKey {
  const _IssuerPublicKey({required this.ax, required this.ay});

  final String ax;
  final String ay;
}
