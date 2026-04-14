import 'dart:convert';

import 'models.dart';
import 'rust_eddsa_helper_ffi.dart';

final BigInt _bn254FieldPrime = BigInt.parse(
  '21888242871839275222246405745257275088548364400416034343698204186575808495617',
);
const int _maxInlineStringBytes = 31;

/// Reduces a bigint to BN254 scalar field.
BigInt fieldReduce(BigInt value) {
  final mod = value % _bn254FieldPrime;
  if (mod.sign >= 0) {
    return mod;
  }
  return mod + _bn254FieldPrime;
}

/// Converts an arbitrary value to BN254 field element.
Future<BigInt> valueToFieldElement(
  Object? value,
  RustEddsaHelperFfi helper,
) async {
  if (value == null) {
    return BigInt.zero;
  }
  if (value is BigInt) {
    return fieldReduce(value);
  }
  if (value is int) {
    return fieldReduce(BigInt.from(value));
  }
  if (value is bool) {
    return value ? BigInt.one : BigInt.zero;
  }
  if (value is String) {
    if (value.startsWith('0x')) {
      return fieldReduce(BigInt.parse(value));
    }
    final decimal = BigInt.tryParse(value);
    if (decimal != null) {
      return fieldReduce(decimal);
    }
    return stringToFieldElement(value, helper);
  }

  // Canonical JSON for deterministic conversion of objects/arrays.
  return stringToFieldElement(canonicalizeJson(value), helper);
}

/// Converts field name to felt:
/// - UTF-8 bytes as bigint if length <= 31 bytes
/// - Poseidon(bits) if length > 31 bytes
Future<BigInt> fieldNameToFieldElement(
  String fieldName,
  RustEddsaHelperFfi helper,
) {
  return stringToFieldElement(fieldName, helper);
}

/// Converts string to felt:
/// - UTF-8 bytes as bigint if length <= 31 bytes
/// - Poseidon(bits) if length > 31 bytes
Future<BigInt> stringToFieldElement(
  String input,
  RustEddsaHelperFfi helper,
) async {
  final bytes = utf8.encode(input);
  if (bytes.isEmpty) {
    return BigInt.zero;
  }

  if (bytes.length <= _maxInlineStringBytes) {
    final hex =
        bytes.map((item) => item.toRadixString(16).padLeft(2, '0')).join();
    return BigInt.parse('0x$hex');
  }

  final bits = _bytesToBits(bytes);
  final hashed = await helper.poseidonHashBits(bits);
  return BigInt.parse(hashed);
}

List<int> _bytesToBits(List<int> bytes) {
  final bits = <int>[];
  // Matches current Rust helper bit packing used for Poseidon(bits).
  for (final byte in bytes) {
    for (var bit = 0; bit < 8; bit += 1) {
      bits.add((byte >> bit) & 1);
    }
  }
  return bits;
}

/// Builds Poseidon commitments from header using alphabetical key order.
Future<List<String>> buildHeaderCommitments(
  Map<String, Object?> header,
  RustEddsaHelperFfi helper,
) async {
  final keys = header.keys.toList(growable: false)..sort();
  final commitments = <String>[];
  for (final key in keys) {
    commitments.add(
      await buildFieldCommitment(
        fieldName: key,
        value: header[key],
        helper: helper,
      ),
    );
  }
  return commitments;
}

/// Builds Poseidon commitments from disclosures preserving disclosure order.
Future<List<String>> buildPayloadCommitments(
  List<Disclosure> disclosures,
  RustEddsaHelperFfi helper,
) async {
  final commitments = <String>[];
  for (final disclosure in disclosures) {
    commitments.add(
      await buildFieldCommitment(
        fieldName: disclosure.field,
        value: disclosure.value,
        helper: helper,
      ),
    );
  }
  return commitments;
}

/// Computes commitment as `poseidon(field_name, value)`.
Future<String> buildFieldCommitment({
  required String fieldName,
  required Object? value,
  required RustEddsaHelperFfi helper,
}) async {
  final fieldElement = await fieldNameToFieldElement(fieldName, helper);
  final valueElement = await valueToFieldElement(value, helper);
  return helper.poseidonHashFieldElements([
    fieldElement.toString(),
    valueElement.toString(),
  ]);
}

/// Computes digest as `poseidon([...headerCommitments, ...payloadCommitments])`.
Future<String> buildDocumentDigest({
  required List<String> headerCommitments,
  required List<String> payloadCommitments,
  required RustEddsaHelperFfi helper,
}) async {
  final finalArray = <String>[...headerCommitments, ...payloadCommitments];
  if (finalArray.isEmpty) {
    throw ArgumentError('Document commitment array cannot be empty.');
  }
  return helper.poseidonHashFieldElements(finalArray);
}
