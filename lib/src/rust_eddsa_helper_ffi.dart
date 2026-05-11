import 'dart:convert';
import 'dart:ffi' as ffi;

import 'package:ffi/ffi.dart';

typedef _PoseidonHashNative =
    ffi.Int32 Function(ffi.Pointer<Utf8>, ffi.Pointer<ffi.Pointer<Utf8>>);
typedef _PoseidonHashBitsNative =
    ffi.Int32 Function(ffi.Pointer<Utf8>, ffi.Pointer<ffi.Pointer<Utf8>>);
typedef _PoseidonFreeStringNative = ffi.Void Function(ffi.Pointer<Utf8>);
typedef _EddsaSignNative =
    ffi.Int32 Function(ffi.Pointer<Utf8>, ffi.Pointer<ffi.Pointer<Utf8>>);
typedef _EddsaVerifyNative =
    ffi.Int32 Function(ffi.Pointer<Utf8>, ffi.Pointer<ffi.Pointer<Utf8>>);
typedef _EddsaFreeStringNative = ffi.Void Function(ffi.Pointer<Utf8>);

@ffi.Native<_PoseidonHashNative>(symbol: 'poseidon_hash')
external int _rustPoseidonHash(
  ffi.Pointer<Utf8> inputJson,
  ffi.Pointer<ffi.Pointer<Utf8>> outputJson,
);

@ffi.Native<_PoseidonHashBitsNative>(symbol: 'poseidon_hash_bits_ffi')
external int _rustPoseidonHashBitsFfi(
  ffi.Pointer<Utf8> inputJson,
  ffi.Pointer<ffi.Pointer<Utf8>> outputJson,
);

@ffi.Native<_PoseidonFreeStringNative>(symbol: 'poseidon_free_string')
external void _rustPoseidonFreeString(ffi.Pointer<Utf8> ptr);

@ffi.Native<_EddsaSignNative>(symbol: 'eddsa_sign')
external int _rustEddsaSign(
  ffi.Pointer<Utf8> inputJson,
  ffi.Pointer<ffi.Pointer<Utf8>> outputJson,
);

@ffi.Native<_EddsaVerifyNative>(symbol: 'eddsa_verify')
external int _rustEddsaVerify(
  ffi.Pointer<Utf8> inputJson,
  ffi.Pointer<ffi.Pointer<Utf8>> outputJson,
);

@ffi.Native<_EddsaFreeStringNative>(symbol: 'eddsa_free_string')
external void _rustEddsaFreeString(ffi.Pointer<Utf8> ptr);

/// Result of EdDSA signing from Rust helper.
class EddsaSignatureResult {
  /// Creates an EdDSA signature result.
  const EddsaSignatureResult({
    required this.ax,
    required this.ay,
    required this.r8x,
    required this.r8y,
    required this.s,
  });

  /// Public key x coordinate.
  final String ax;

  /// Public key y coordinate.
  final String ay;

  /// Signature R8 x coordinate.
  final String r8x;

  /// Signature R8 y coordinate.
  final String r8y;

  /// Signature scalar S.
  final String s;
}

/// Result of public key derivation from private key.
class EddsaPublicKeyResult {
  /// Creates a public key result.
  const EddsaPublicKeyResult({required this.ax, required this.ay});

  /// Public key x coordinate.
  final String ax;

  /// Public key y coordinate.
  final String ay;
}

/// FFI wrapper around Rust helper (Poseidon + EdDSA).
///
/// Native code is built and bundled via `hook/build.dart` (Dart hooks). Supported
/// targets: macOS, iOS, Android, Linux, and Windows.
class RustEddsaHelperFfi {
  /// Creates helper; symbols resolve against the bundled `rust_eddsa_helper`
  /// dynamic library from the build hook.
  RustEddsaHelperFfi();

  /// Runs Poseidon hash over field elements represented as decimal strings.
  Future<String> poseidonHashFieldElements(List<String> inputs) async {
    if (inputs.isEmpty) {
      throw ArgumentError('Poseidon inputs cannot be empty.');
    }
    final requestJson = jsonEncode({'inputs': inputs});
    final requestPtr = requestJson.toNativeUtf8();
    final responsePtr = malloc<ffi.Pointer<Utf8>>();

    try {
      final code = _rustPoseidonHash(requestPtr, responsePtr);
      final response = _parseRustJson(
        code: code,
        responsePtr: responsePtr.value,
        freeString: _rustPoseidonFreeString,
        operationName: 'poseidon_hash',
      );
      final result = response['result']?.toString();
      if (result == null || result.isEmpty) {
        throw StateError('poseidon_hash returned empty result.');
      }
      return result;
    } finally {
      malloc.free(responsePtr);
      malloc.free(requestPtr);
    }
  }

  /// Runs Poseidon hash over raw bits (`0` or `1`).
  Future<String> poseidonHashBits(List<int> bits) async {
    for (final bit in bits) {
      if (bit != 0 && bit != 1) {
        throw ArgumentError('Bits must be either 0 or 1.');
      }
    }
    final requestJson = jsonEncode({'bits': bits});
    final requestPtr = requestJson.toNativeUtf8();
    final responsePtr = malloc<ffi.Pointer<Utf8>>();

    try {
      final code = _rustPoseidonHashBitsFfi(requestPtr, responsePtr);
      final response = _parseRustJson(
        code: code,
        responsePtr: responsePtr.value,
        freeString: _rustPoseidonFreeString,
        operationName: 'poseidon_hash_bits_ffi',
      );
      final result = response['result']?.toString();
      if (result == null || result.isEmpty) {
        throw StateError('poseidon_hash_bits_ffi returned empty result.');
      }
      return result;
    } finally {
      malloc.free(responsePtr);
      malloc.free(requestPtr);
    }
  }

  /// Signs a pre-hashed Poseidon digest.
  Future<EddsaSignatureResult> signDigest({
    required String msgHash,
    required String privateKeyHex,
  }) async {
    final requestJson = jsonEncode({
      'operation': 'sign',
      'data': {'msgHash': msgHash, 'privateKeyHex': privateKeyHex},
    });
    final requestPtr = requestJson.toNativeUtf8();
    final responsePtr = malloc<ffi.Pointer<Utf8>>();

    try {
      final code = _rustEddsaSign(requestPtr, responsePtr);
      final response = _parseRustJson(
        code: code,
        responsePtr: responsePtr.value,
        freeString: _rustEddsaFreeString,
        operationName: 'eddsa_sign',
      );
      final result = response['result'];
      if (result is! Map<String, dynamic>) {
        throw StateError('eddsa_sign returned invalid result object.');
      }
      return EddsaSignatureResult(
        ax: result['Ax'].toString(),
        ay: result['Ay'].toString(),
        r8x: result['R8x'].toString(),
        r8y: result['R8y'].toString(),
        s: result['S'].toString(),
      );
    } finally {
      malloc.free(responsePtr);
      malloc.free(requestPtr);
    }
  }

  /// Derives BabyJubJub public key coordinates from private key hex.
  Future<EddsaPublicKeyResult> derivePublicKey({
    required String privateKeyHex,
  }) async {
    final requestJson = jsonEncode({
      'operation': 'derivePublicKey',
      'data': {'privateKeyHex': privateKeyHex},
    });
    final requestPtr = requestJson.toNativeUtf8();
    final responsePtr = malloc<ffi.Pointer<Utf8>>();

    try {
      final code = _rustEddsaSign(requestPtr, responsePtr);
      final response = _parseRustJson(
        code: code,
        responsePtr: responsePtr.value,
        freeString: _rustEddsaFreeString,
        operationName: 'eddsa_sign',
      );
      final result = response['result'];
      if (result is! Map<String, dynamic>) {
        throw StateError('eddsa_sign returned invalid result object.');
      }
      final ax = result['Ax']?.toString();
      final ay = result['Ay']?.toString();
      if (ax == null || ax.isEmpty || ay == null || ay.isEmpty) {
        throw StateError('eddsa_sign derivePublicKey returned empty Ax/Ay.');
      }
      return EddsaPublicKeyResult(ax: ax, ay: ay);
    } finally {
      malloc.free(responsePtr);
      malloc.free(requestPtr);
    }
  }

  /// Verifies EdDSA signature over a pre-hashed Poseidon digest.
  Future<bool> verifyDigestSignature({
    required String msgHash,
    required String publicKeyAx,
    required String publicKeyAy,
    required String r8x,
    required String r8y,
    required String s,
  }) async {
    final requestJson = jsonEncode({
      'operation': 'verify',
      'data': {
        'msgHash': msgHash,
        'publicKeyAx': publicKeyAx,
        'publicKeyAy': publicKeyAy,
        'R8x': r8x,
        'R8y': r8y,
        'S': s,
      },
    });
    final requestPtr = requestJson.toNativeUtf8();
    final responsePtr = malloc<ffi.Pointer<Utf8>>();

    try {
      final code = _rustEddsaVerify(requestPtr, responsePtr);
      final response = _parseRustJson(
        code: code,
        responsePtr: responsePtr.value,
        freeString: _rustEddsaFreeString,
        operationName: 'eddsa_verify',
      );
      return response['result'] == true;
    } finally {
      malloc.free(responsePtr);
      malloc.free(requestPtr);
    }
  }

  Map<String, dynamic> _parseRustJson({
    required int code,
    required ffi.Pointer<Utf8> responsePtr,
    required void Function(ffi.Pointer<Utf8>) freeString,
    required String operationName,
  }) {
    if (responsePtr == ffi.nullptr) {
      throw StateError('$operationName returned null response pointer.');
    }

    final responseString = responsePtr.toDartString();
    freeString(responsePtr);

    final decoded = jsonDecode(responseString);
    if (decoded is! Map<String, dynamic>) {
      throw StateError('$operationName returned malformed JSON.');
    }
    if (decoded['success'] != true || code != 0) {
      throw StateError(
        '$operationName failed: ${decoded['error'] ?? 'unknown error'}',
      );
    }
    return decoded;
  }
}
