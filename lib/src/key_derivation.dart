import 'rust_eddsa_helper_ffi.dart';

/// BabyJubJub public key coordinates as decimal field strings.
class BabyJubPublicKey {
  /// Creates a BabyJubJub public key.
  const BabyJubPublicKey({
    required this.ax,
    required this.ay,
  });

  /// X coordinate.
  final String ax;

  /// Y coordinate.
  final String ay;

  /// Comma-separated representation (`Ax,Ay`) used by some header formats.
  String asCommaSeparated() => '$ax,$ay';
}

/// Helper for deriving BabyJubJub public keys from private key hex.
class VcKeyDerivation {
  /// Creates key derivation helper with optional injected Rust bridge.
  VcKeyDerivation({RustEddsaHelperFfi? crypto})
      : _crypto = crypto ?? RustEddsaHelperFfi();

  final RustEddsaHelperFfi _crypto;

  /// Derives BabyJubJub public key coordinates from a 32-byte private key hex.
  Future<BabyJubPublicKey> derivePublicKey({
    required String privateKeyHex,
  }) async {
    final derived = await _crypto.derivePublicKey(
      privateKeyHex: privateKeyHex,
    );
    return BabyJubPublicKey(ax: derived.ax, ay: derived.ay);
  }
}