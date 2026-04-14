import 'dart:convert';
import 'dart:ffi' as ffi;
import 'dart:io';

import 'package:ffi/ffi.dart';

typedef _PoseidonHashNative = ffi.Int32 Function(
    ffi.Pointer<Utf8>, ffi.Pointer<ffi.Pointer<Utf8>>);
typedef _PoseidonHashDart = int Function(
    ffi.Pointer<Utf8>, ffi.Pointer<ffi.Pointer<Utf8>>);
typedef _PoseidonHashBitsNative = ffi.Int32 Function(
    ffi.Pointer<Utf8>, ffi.Pointer<ffi.Pointer<Utf8>>);
typedef _PoseidonHashBitsDart = int Function(
    ffi.Pointer<Utf8>, ffi.Pointer<ffi.Pointer<Utf8>>);

typedef _PoseidonFreeStringNative = ffi.Void Function(ffi.Pointer<Utf8>);
typedef _PoseidonFreeStringDart = void Function(ffi.Pointer<Utf8>);

typedef _EddsaSignNative = ffi.Int32 Function(
    ffi.Pointer<Utf8>, ffi.Pointer<ffi.Pointer<Utf8>>);
typedef _EddsaSignDart = int Function(
    ffi.Pointer<Utf8>, ffi.Pointer<ffi.Pointer<Utf8>>);
typedef _EddsaVerifyNative = ffi.Int32 Function(
    ffi.Pointer<Utf8>, ffi.Pointer<ffi.Pointer<Utf8>>);
typedef _EddsaVerifyDart = int Function(
    ffi.Pointer<Utf8>, ffi.Pointer<ffi.Pointer<Utf8>>);

typedef _EddsaFreeStringNative = ffi.Void Function(ffi.Pointer<Utf8>);
typedef _EddsaFreeStringDart = void Function(ffi.Pointer<Utf8>);

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

/// FFI wrapper around Rust helper (Poseidon + EdDSA).
class RustEddsaHelperFfi {
  /// Creates helper and loads dynamic library.
  RustEddsaHelperFfi({ffi.DynamicLibrary? library})
      : _lib = library ?? _openDynamicLibrary() {
    _poseidonHash = _lib
        .lookup<ffi.NativeFunction<_PoseidonHashNative>>('poseidon_hash')
        .asFunction<_PoseidonHashDart>();
    _poseidonHashBits = _lib
        .lookup<ffi.NativeFunction<_PoseidonHashBitsNative>>(
          'poseidon_hash_bits_ffi',
        )
        .asFunction<_PoseidonHashBitsDart>();
    _poseidonFreeString = _lib
        .lookup<ffi.NativeFunction<_PoseidonFreeStringNative>>(
          'poseidon_free_string',
        )
        .asFunction<_PoseidonFreeStringDart>();

    _eddsaSign = _lib
        .lookup<ffi.NativeFunction<_EddsaSignNative>>('eddsa_sign')
        .asFunction<_EddsaSignDart>();
    _eddsaVerify = _lib
        .lookup<ffi.NativeFunction<_EddsaVerifyNative>>('eddsa_verify')
        .asFunction<_EddsaVerifyDart>();
    _eddsaFreeString = _lib
        .lookup<ffi.NativeFunction<_EddsaFreeStringNative>>(
          'eddsa_free_string',
        )
        .asFunction<_EddsaFreeStringDart>();
  }

  final ffi.DynamicLibrary _lib;
  late final _PoseidonHashDart _poseidonHash;
  late final _PoseidonHashBitsDart _poseidonHashBits;
  late final _PoseidonFreeStringDart _poseidonFreeString;
  late final _EddsaSignDart _eddsaSign;
  late final _EddsaVerifyDart _eddsaVerify;
  late final _EddsaFreeStringDart _eddsaFreeString;

  /// Runs Poseidon hash over field elements represented as decimal strings.
  Future<String> poseidonHashFieldElements(List<String> inputs) async {
    if (inputs.isEmpty) {
      throw ArgumentError('Poseidon inputs cannot be empty.');
    }
    final requestJson = jsonEncode({'inputs': inputs});
    final requestPtr = requestJson.toNativeUtf8();
    final responsePtr = malloc<ffi.Pointer<Utf8>>();

    try {
      final code = _poseidonHash(requestPtr, responsePtr);
      final response = _parseRustJson(
        code: code,
        responsePtr: responsePtr.value,
        freeString: _poseidonFreeString,
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
      final code = _poseidonHashBits(requestPtr, responsePtr);
      final response = _parseRustJson(
        code: code,
        responsePtr: responsePtr.value,
        freeString: _poseidonFreeString,
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
      final code = _eddsaSign(requestPtr, responsePtr);
      final response = _parseRustJson(
        code: code,
        responsePtr: responsePtr.value,
        freeString: _eddsaFreeString,
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
      final code = _eddsaVerify(requestPtr, responsePtr);
      final response = _parseRustJson(
        code: code,
        responsePtr: responsePtr.value,
        freeString: _eddsaFreeString,
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

  static ffi.DynamicLibrary _openDynamicLibrary() {
    final libraryName = _dynamicLibraryName();
    final candidates = <String>[
      '${Directory.current.path}/lib/rust_eddsa_helper/target/release/$libraryName',
      '${Directory.current.path}/rust_eddsa_helper/target/release/$libraryName',
      libraryName,
    ];

    for (final candidate in candidates) {
      try {
        return ffi.DynamicLibrary.open(candidate);
      } on Object {
        continue;
      }
    }

    throw StateError(
      'Unable to load Rust helper library. Tried: ${candidates.join(', ')}',
    );
  }

  static String _dynamicLibraryName() {
    if (Platform.isMacOS) {
      return 'librust_eddsa_helper.dylib';
    }
    if (Platform.isLinux || Platform.isAndroid) {
      return 'librust_eddsa_helper.so';
    }
    if (Platform.isWindows) {
      return 'rust_eddsa_helper.dll';
    }
    throw UnsupportedError(
      'Unsupported platform: ${Platform.operatingSystem}.',
    );
  }
}
