import 'dart:convert';

/// A field disclosure entry for the VC payload.
class Disclosure {
  /// Creates a disclosure.
  const Disclosure({
    required this.field,
    required this.value,
  });

  /// Claim field name.
  final String field;

  /// Claim value.
  final Object? value;

  /// Converts this disclosure to JSON.
  Map<String, Object?> toJson() => {
        'field': field,
        'value': value,
      };

  /// Builds a disclosure from JSON.
  factory Disclosure.fromJson(Map<String, dynamic> json) {
    final field = json['field'];
    if (field is! String || field.isEmpty) {
      throw ArgumentError('Disclosure field must be a non-empty string.');
    }
    return Disclosure(
      field: field,
      value: json['value'],
    );
  }
}

/// Signature for an untraceable ZK VC document.
class VcSignature {
  /// Creates a signature object.
  const VcSignature({
    required this.r8,
    required this.s,
  });

  /// EdDSA `R8` point `[R8x, R8y]` as decimal field elements.
  final List<String> r8;

  /// EdDSA `S` scalar as decimal field element.
  final String s;

  /// Converts this signature to JSON.
  Map<String, Object?> toJson() => {
        'R8': r8,
        'S': s,
      };

  /// Builds signature from JSON.
  factory VcSignature.fromJson(Map<String, dynamic> json) {
    final r8Raw = json['R8'];
    final sRaw = json['S'];
    if (r8Raw is! List || r8Raw.length != 2) {
      throw ArgumentError('Signature.R8 must be an array of two strings.');
    }
    final r8 = r8Raw.map((item) => item.toString()).toList(growable: false);
    final s = sRaw?.toString();
    if (s == null || s.isEmpty) {
      throw ArgumentError('Signature.S must be provided.');
    }
    return VcSignature(r8: r8, s: s);
  }
}

/// Signed untraceable VC document.
class SignedVcDocument {
  /// Creates a signed VC document.
  const SignedVcDocument({
    required this.header,
    required this.disclosures,
    required this.headerCommitments,
    required this.payloadCommitments,
    required this.signature,
  });

  /// Header object.
  final Map<String, Object?> header;

  /// Disclosures.
  final List<Disclosure> disclosures;

  /// Poseidon commitments for sorted header fields.
  final List<String> headerCommitments;

  /// Poseidon commitments for disclosure fields.
  final List<String> payloadCommitments;

  /// EdDSA signature over Poseidon digest of commitments.
  final VcSignature signature;

  /// Converts this document to JSON shape requested by circuits.
  Map<String, Object?> toJson() => {
        'header': header,
        'disclosures': disclosures.map((item) => item.toJson()).toList(),
        'header_commitments': headerCommitments,
        'payload_commitments': payloadCommitments,
        'signature': signature.toJson(),
      };

  /// Builds a signed VC document from JSON.
  factory SignedVcDocument.fromJson(Map<String, dynamic> json) {
    final headerRaw = json['header'];
    if (headerRaw is! Map<String, dynamic>) {
      throw ArgumentError('Document.header must be a JSON object.');
    }
    final disclosuresRaw = json['disclosures'];
    if (disclosuresRaw is! List) {
      throw ArgumentError('Document.disclosures must be an array.');
    }
    final headerCommitmentsRaw = json['header_commitments'];
    final payloadCommitmentsRaw = json['payload_commitments'];
    final signatureRaw = json['signature'];
    if (signatureRaw is! Map<String, dynamic>) {
      throw ArgumentError('Document.signature must be a JSON object.');
    }

    return SignedVcDocument(
      header: Map<String, Object?>.from(headerRaw),
      disclosures: disclosuresRaw
          .map((item) => Disclosure.fromJson(Map<String, dynamic>.from(item)))
          .toList(growable: false),
      headerCommitments: headerCommitmentsRaw is List
          ? headerCommitmentsRaw.map((item) => item.toString()).toList()
          : const [],
      payloadCommitments: payloadCommitmentsRaw is List
          ? payloadCommitmentsRaw.map((item) => item.toString()).toList()
          : const [],
      signature: VcSignature.fromJson(signatureRaw),
    );
  }
}

/// Creates a stable, canonical JSON string with sorted map keys.
String canonicalizeJson(Object? value) {
  Object? normalize(Object? current) {
    if (current is Map) {
      final sortedKeys = current.keys.map((key) => key.toString()).toList()
        ..sort();
      final normalized = <String, Object?>{};
      for (final key in sortedKeys) {
        normalized[key] = normalize(current[key]);
      }
      return normalized;
    }
    if (current is List) {
      return current.map(normalize).toList(growable: false);
    }
    return current;
  }

  return jsonEncode(normalize(value));
}
