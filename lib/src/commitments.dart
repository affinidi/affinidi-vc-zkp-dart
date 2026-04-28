import 'dart:convert';

import 'models.dart';
import 'rust_eddsa_helper_ffi.dart';

final BigInt _bn254FieldPrime = BigInt.parse(
  '21888242871839275222246405745257275088548364400416034343698204186575808495617',
);
const int _maxInlineStringBytes = 31;
final BigInt _typeTagNull = BigInt.zero;
final BigInt _typeTagBool = BigInt.one;
final BigInt _typeTagInt = BigInt.from(2);
final BigInt _typeTagString = BigInt.from(3);
final BigInt _typeTagObject = BigInt.from(4);
final BigInt _typeTagArray = BigInt.from(5);
const Set<String> _numericStringIntFields = <String>{'holderAx', 'holderAy'};
const Set<String> _reservedDisclosureFieldNames = <String>{
  'holderAx',
  'holderAy',
  'issuer',
  'schema',
  'version',
  'issued_at',
  'expires_at',
};

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
  final encoded = await _encodeValueWithType(value, helper);
  return encoded.payload;
}

/// Converts field name to felt:
/// - UTF-8 bytes as bigint if length <= 31 bytes
/// - Poseidon(bits) if length > 31 bytes
Future<BigInt> fieldNameToFieldElement(
  String fieldName,
  RustEddsaHelperFfi helper,
) async {
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
    final hex = bytes
        .map((item) => item.toRadixString(16).padLeft(2, '0'))
        .join();
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
  for (var index = 0; index < keys.length; index += 1) {
    final key = keys[index];
    commitments.add(
      await buildFieldCommitment(
        index: index,
        fieldName: key,
        value: header[key],
        helper: helper,
      ),
    );
  }
  return commitments;
}

/// Builds payload commitments using canonical payload field order.
///
/// Payload fields are sorted alphabetically by field name to guarantee stable
/// commitment indexes across issuers/holders/verifiers.
Future<List<String>> buildPayloadCommitments(
  List<Disclosure> disclosures,
  RustEddsaHelperFfi helper,
) async {
  final sorted = disclosures.toList(growable: false)
    ..sort((left, right) => left.field.compareTo(right.field));

  for (var index = 1; index < sorted.length; index += 1) {
    if (sorted[index - 1].field == sorted[index].field) {
      throw ArgumentError(
        'Duplicate payload field "${sorted[index].field}" is not allowed.',
      );
    }
  }

  final commitments = <String>[];
  for (var index = 0; index < sorted.length; index += 1) {
    final disclosure = sorted[index];
    if (_reservedDisclosureFieldNames.contains(disclosure.field)) {
      throw ArgumentError(
        'Disclosure field name "${disclosure.field}" is reserved for header use.',
      );
    }
    commitments.add(
      await buildFieldCommitment(
        index: index,
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
  required int index,
  required String fieldName,
  required Object? value,
  required RustEddsaHelperFfi helper,
}) async {
  final fieldElement = await fieldNameToFieldElement(fieldName, helper);
  final encodedValue = await _encodeValueWithType(
    value,
    helper,
    forceNumericStringAsInt: _numericStringIntFields.contains(fieldName),
  );
  return helper.poseidonHashFieldElements([
    index.toString(),
    fieldElement.toString(),
    encodedValue.typeTag.toString(),
    encodedValue.payload.toString(),
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
  if (finalArray.length == 1) {
    throw ArgumentError(
      'Document commitment array cannot contain a single element. '
      'Use at least two field elements for Poseidon domain separation.',
    );
  }
  return helper.poseidonHashFieldElements(finalArray);
}

Future<_EncodedValue> _encodeValueWithType(
  Object? value,
  RustEddsaHelperFfi helper, {
  bool forceNumericStringAsInt = false,
}) async {
  if (value == null) {
    return _EncodedValue(typeTag: _typeTagNull, payload: BigInt.zero);
  }
  if (value is bool) {
    return _EncodedValue(
      typeTag: _typeTagBool,
      payload: value ? BigInt.one : BigInt.zero,
    );
  }
  if (value is BigInt) {
    return _EncodedValue(typeTag: _typeTagInt, payload: fieldReduce(value));
  }
  if (value is int) {
    return _EncodedValue(
      typeTag: _typeTagInt,
      payload: fieldReduce(BigInt.from(value)),
    );
  }
  if (value is String) {
    final trimmed = value.trim();
    if (forceNumericStringAsInt) {
      final parsedNumeric = _tryParseNumericString(trimmed);
      if (parsedNumeric == null) {
        throw ArgumentError(
          'Expected numeric string for holder coordinate field, got "$value".',
        );
      }
      return _EncodedValue(
        typeTag: _typeTagInt,
        payload: fieldReduce(parsedNumeric),
      );
    }
    return _EncodedValue(
      typeTag: _typeTagString,
      payload: await stringToFieldElement(value, helper),
    );
  }
  if (value is List) {
    return _EncodedValue(
      typeTag: _typeTagArray,
      payload: await stringToFieldElement(canonicalizeJson(value), helper),
    );
  }
  return _EncodedValue(
    typeTag: _typeTagObject,
    payload: await stringToFieldElement(canonicalizeJson(value), helper),
  );
}

BigInt? _tryParseNumericString(String value) {
  if (value.isEmpty) {
    return null;
  }
  final hexPattern = RegExp(r'^-?0x[0-9a-fA-F]+$');
  final decPattern = RegExp(r'^-?[0-9]+$');
  if (hexPattern.hasMatch(value) || decPattern.hasMatch(value)) {
    return BigInt.parse(value);
  }
  return null;
}

class _EncodedValue {
  const _EncodedValue({required this.typeTag, required this.payload});

  final BigInt typeTag;
  final BigInt payload;
}
