import 'dart:typed_data';
import 'package:pinenacl/api.dart';
//part of bip32_ed25519.api;

class InvalidSigningKeyError extends Error {}

class ExtendedSigningKey extends SigningKey {
  // Throws Error as it is very dangerous to have non prune-to-buffered bytes.
  ExtendedSigningKey(List<int> secretBytes) : this.fromValidBytes(secretBytes);
  ExtendedSigningKey.fromSeed(List<int> seed) : this(_seedToSecret(seed));

  ExtendedSigningKey.decode(String keyString, {Encoder coder = decoder})
      : this(coder.decode(keyString));

  ExtendedSigningKey.generate()
      : this.normalizeBytes(TweetNaCl.randombytes(keyLength));

  ExtendedSigningKey.normalizeBytes(List<int> secretBytes)
      : this.fromValidBytes(clampKey(secretBytes, keyLength),
            keyLength: keyLength);

  ExtendedSigningKey.fromValidBytes(List<int> secret,
      {int keyLength = keyLength})
      : super.fromValidBytes(validateKeyBits(secret), keyLength: keyLength);

  static List<int> _seedToSecret(List<int> seed) {
    if (seed.length != seedSize) {
      throw Exception(
          'Seed\'s length (${seed.length}) must be $seedSize long.');
    }
    final extendedSecret = Hash.sha512(seed);
    return clampKey(extendedSecret, keyLength);
  }

  static VerifyKey _toPublic(List<int> secret) {
    var pk = Uint8List(TweetNaCl.publicKeyLength);
    TweetNaClExt.scalar_base(pk, Uint8List.fromList(secret));
    return VerifyKey(pk);
  }

  static const seedSize = TweetNaCl.seedSize;

  @override
  final int prefixLength = keyLength;

  static const keyLength = 64;

  VerifyKey? _verifyKey;

  @override
  VerifyKey get verifyKey => _verifyKey ??= _toPublic(this);

  @override
  VerifyKey get publicKey => verifyKey;

  ByteList get keyBytes => prefix;

  /// Throws an error on invalid bytes and return the bytes itself anyway
  static List<int> validateKeyBits(List<int> bytes) {
    var valid = ((bytes[0] & 7) == 0) && ((bytes[31] & 192) == 64);
    if (bytes.length < 32 || !valid) {
      throw InvalidSigningKeyError();
    }

    return bytes;
  }

  static List<int> clampKey(List<int> bytes, int byteLength) {
    if (bytes.length != byteLength) {
      throw InvalidSigningKeyError();
    }
    var resultBytes = List<int>.from(bytes);
    resultBytes[0] &= 248;
    resultBytes[31] &= 127;
    resultBytes[31] |= 64;
    return resultBytes;
  }

  @override
  //SignedMessage sign(List<int> message, {bool extended: false}) => super.sign(message, extended: true);
  SignedMessage sign(List<int> message) {
    // signed message
    var sm = Uint8List(message.length + TweetNaCl.signatureLength);
    var kb = Uint8List.fromList(this.keyBytes + publicKey);
    final result = TweetNaCl.crypto_sign(
        sm, -1, Uint8List.fromList(message), 0, message.length, kb,
        extended: true);
    if (result != 0) {
      throw Exception('Signing the massage is failed');
    }

    return SignedMessage.fromList(signedMessage: sm);
  }

  static const decoder = Bech32Coder(hrp: 'ed25519e_sk');

  @override
  Encoder get encoder => decoder;
}
