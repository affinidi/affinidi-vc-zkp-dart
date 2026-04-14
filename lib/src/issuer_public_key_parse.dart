/// BabyJubJub coordinates when `header['issuer']` is `Ax,Ay` (decimal or `0x` hex).
///
/// Other `issuer` values (for example a DID) do not match this shape; resolve
/// keys outside this library and pass them to [VcVerifier.verifyDocument].
class IssuerBabyJubCoords {
  /// Creates parsed issuer coordinates.
  const IssuerBabyJubCoords({
    required this.ax,
    required this.ay,
  });

  /// Field element x as decimal string.
  final String ax;

  /// Field element y as decimal string.
  final String ay;
}

String _normalizeFieldElementString(String value) {
  final trimmed = value.trim();
  if (trimmed.startsWith('0x') || trimmed.startsWith('0X')) {
    return BigInt.parse(trimmed).toString();
  }
  return trimmed;
}

/// Parses `issuer` header when it is comma-separated `x,y` (optional spaces).
///
/// Returns `null` if the value is not exactly two comma-separated parts (for
/// example a DID). Only `,` is treated as a separator so values with `:` stay
/// opaque.
IssuerBabyJubCoords? tryParseIssuerBabyJubCommaSeparated(String? issuerRaw) {
  if (issuerRaw == null) {
    return null;
  }
  final trimmed = issuerRaw.trim();
  if (trimmed.isEmpty || !trimmed.contains(',')) {
    return null;
  }
  final parts = trimmed
      .split(',')
      .map((p) => p.trim())
      .where((p) => p.isNotEmpty)
      .toList(growable: false);
  if (parts.length != 2) {
    return null;
  }
  return IssuerBabyJubCoords(
    ax: _normalizeFieldElementString(parts[0]),
    ay: _normalizeFieldElementString(parts[1]),
  );
}
