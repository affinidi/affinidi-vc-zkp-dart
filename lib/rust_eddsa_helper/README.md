# Rust EdDSA Helper

This Rust library provides EdDSA signing functionality via FFI for use in Flutter mobile applications.

## Building

To build the library for your target platform:

```bash
# For macOS
cargo build --release

# For iOS (requires iOS toolchain). Use --profile ios so the static lib
# has visible C symbols (eddsa_sign, eddsa_free_string); release uses LTO
# which can hide them from the linker.
cargo build --profile ios --target aarch64-apple-ios
cargo build --profile ios --target x86_64-apple-ios   # Simulator

# For Android (requires Android NDK)
# See Flutter documentation for setting up Android NDK
cargo build --release --target aarch64-linux-android
cargo build --release --target armv7-linux-androideabi
cargo build --release --target i686-linux-android
cargo build --release --target x86_64-linux-android
```

The compiled library will be in `target/<triple>/release/` (or `target/<triple>/ios/` for iOS):
- macOS: `librust_eddsa_helper.dylib`
- Linux: `librust_eddsa_helper.so`
- iOS: `target/aarch64-apple-ios/ios/librust_eddsa_helper.a` (static library; use `--profile ios`). Run `./build_ios.sh` to build and verify symbols.
- Android: `librust_eddsa_helper.so`

## Integration with Flutter

1. Build the library for your target platforms
2. Copy the library files to your Flutter project:
   - iOS: Add to `ios/Runner/` and update `ios/Runner.xcodeproj`
   - Android: Add to `android/app/src/main/jniLibs/<abi>/`

3. Update your `pubspec.yaml` to include the `ffi` package:
```yaml
dependencies:
  ffi: ^2.0.1
```

## Testing

```bash
cargo test
```

