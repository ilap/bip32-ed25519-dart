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

  // prefixLength has a late binding
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
  factory Bip32SigningKey(List<int> secretKey) {
    if (!isValidBits(secretKey)) {
      throw Exception('Secret is not valid BIP32-ED25519 Extended key');
    }
    return Bip32SigningKey.normalizeBytes(secretKey);
  }

  Bip32SigningKey.normalizeBytes(List<int> secretBytes, {int depth = 0})
      : this.fromValidBytes(
            setBits(secretBytes), _toPublic(setBits(secretBytes)),
            secretLength: keyLength);

  factory Bip32SigningKey.decode(String key, {Encoder coder = decoder}) {
    final decoded = coder.decode(key);
    return Bip32SigningKey(decoded);
  }

  Bip32SigningKey.fromValidBytes(List<int> secret, List<int> public,
      {int secretLength = keyLength, this.depth = 0})
      : _verifyKey = Bip32VerifyKey(public),
        super.fromValidBytes(setBits(secret), _toPublic(setBits(secret)),
            secretLength: keyLength) {
    _chainCode = ChainCode(suffix);
  }

  Bip32SigningKey.fromVerifiedBytes(List<int> verifiedBytes, {int depth = 0})
      : this.fromValidBytes(verifiedBytes, _toPublic(verifiedBytes),
            secretLength: keyLength);

  Bip32SigningKey.generate()
      : this.normalizeBytes(TweetNaCl.randombytes(keyLength));

  static VerifyKey _toPublic(List<int> secret) {
    var left = List.filled(TweetNaCl.publicKeyLength, 0);
    var pk = Uint8List.fromList(
        left + secret.sublist(keyLength - ChainCode.chainCodeLength));

    TweetNaClExt.scalar_base(pk, Uint8List.fromList(secret));
    return Bip32VerifyKey(pk);
  }

  static bool isValidBits(List<int> bytes) {
    return ExtendedSigningKey.isValidBits(bytes) && (bytes[31] & 32) == 0;
  }

  static List<int> setBits(List<int> bytes) {
    bytes = ExtendedSigningKey.setBits(bytes);
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
  final Bip32VerifyKey _verifyKey;

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
