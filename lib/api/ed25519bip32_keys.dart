import 'dart:typed_data';

import 'package:bip32_ed25519/api/ed25519e_keys.dart';
import 'package:bip32_ed25519/api.dart';

class Bip32VerifyKey extends VerifyKey with Bip32PublicKey {
  Bip32VerifyKey(List<int> publicBytes, {this.depth = 0})
      : super(publicBytes, keyLength) {
    _chainCode = ChainCode(suffix);
  }

  Bip32VerifyKey.decode(String data, {Encoder coder = decoder, this.depth = 0})
      : super.decode(data, coder: coder) {
    _chainCode = ChainCode(suffix);
  }

  Bip32VerifyKey.fromKeyBytes(List<int> pubBytes, List<int> chainCodeBytes,
      {int depth = 0})
      : this(pubBytes.toList() + chainCodeBytes.toList(), depth: depth);

  @override
  final int prefixLength = keyLength - ChainCode.chainCodeLength;

  static const keyLength = 64;
  final int depth;

  ByteList get keyBytes => prefix;

  late final ChainCode _chainCode;

  @override
  ChainCode get chainCode => _chainCode;

  @override
  Bip32VerifyKey derive(index) {
    return this;
  }

  static const decoder = Bech32Coder(hrp: 'xpub');

  @override
  Encoder get encoder => decoder;
}

class Bip32SigningKey extends ExtendedSigningKey with Bip32PrivateKey {
  /// Throws Error as it is very dangerous to have non prune-to-buffered bytes.
  Bip32SigningKey(List<int> secretBytes)
      : this.normalizeBytes(validateKeyBits(secretBytes));

  Bip32SigningKey.decode(String key, {Encoder coder = decoder})
      : this(coder.decode(key));

  Bip32SigningKey.generate()
      : this.normalizeBytes(TweetNaCl.randombytes(keyLength));

  Bip32SigningKey.normalizeBytes(List<int> secretBytes, {int depth = 0})
      : this.fromValidBytes(clampKey(secretBytes), depth: depth);

  Bip32SigningKey.fromValidBytes(List<int> secret, {this.depth = 0})
      : super.fromValidBytes(validateKeyBits(secret), keyLength: keyLength) {
    /// TODO super.verifyKey;
    _verifyKey = _toPublic(validateKeyBits(secret));
    _chainCode = ChainCode(suffix);
  }

  Bip32SigningKey.fromKeyBytes(List<int> secret, List<int> chainCode,
      {int depth = 0})
      : this.fromValidBytes(secret.toList() + chainCode.toList(), depth: depth);

  static Bip32VerifyKey _toPublic(List<int> secret) {
    var left = List.filled(TweetNaCl.publicKeyLength, 0);
    var pk = Uint8List.fromList(
        left + secret.sublist(keyLength - ChainCode.chainCodeLength));

    TweetNaClExt.scalar_base(pk, Uint8List.fromList(secret));
    return Bip32VerifyKey(pk);
  }

  static List<int> validateKeyBits(List<int> bytes) {
    bytes = ExtendedSigningKey.validateKeyBits(bytes);

    if ((bytes[31] & 32) != 0) {
      throw InvalidSigningKeyError();
    }
    return bytes;
  }

  static List<int> clampKey(List<int> bytes) {
    bytes = ExtendedSigningKey.clampKey(bytes, keyLength);
    // clear the 3rd bit
    bytes[31] &= 223;
    return bytes;
  }

  // prefixLength is a late binding variable.
  @override
  final int prefixLength = keyLength - ChainCode.chainCodeLength;

  static const keyLength = 96;

  final int depth;

  ByteList get keyBytes => prefix;

  @override
  ChainCode get chainCode => _chainCode;
  late final ChainCode _chainCode;
  late final Bip32VerifyKey _verifyKey;

  @override
  Bip32VerifyKey get verifyKey => _verifyKey;

  @override
  VerifyKey get publicKey => super.verifyKey;

  @override
  Bip32SigningKey derive(index) {
    return this;
  }

  @override
  Bip32SigningKey master(List<int> seed) {
    return this;
  }

  static const decoder = Bech32Coder(hrp: 'xprv');

  @override
  Encoder get encoder => decoder;
}
