import 'dart:typed_data';
import 'package:pinenacl/api.dart';
//part of bip32_ed25519.api;

class ExtendedSigningKey extends SigningKey {
  /// Throws Error as it is very dangerous to have non prune-to-buffered bytes.
  factory ExtendedSigningKey(List<int> extendedKey) {
    if (!isValidBits(extendedKey)) {
      throw Exception('Secret is not valid ED25519 Extended key');
    }
    return ExtendedSigningKey.normalizeBytes(extendedKey);
  }

  factory ExtendedSigningKey.decode(String key, {Encoder coder = decoder}) {
    final decoded = coder.decode(key);
    return ExtendedSigningKey(decoded);
  }

  ExtendedSigningKey.normalizeBytes(List<int> secretBytes)
      : this.fromValidBytes(setBits(secretBytes), _toPublic(setBits(secretBytes)), secretLength: extendedKeySize);

  ExtendedSigningKey.fromValidBytes(List<int> secret, List<int> public, {int secretLength = TweetNaCl.signingKeyLength})
      : super.fromValidBytes(setBits(secret), _toPublic(setBits(secret)), secretLength: secretLength);

  ExtendedSigningKey.fromVerifiedBytes(List<int> verifiedBytes)
      : this.fromValidBytes(verifiedBytes, _toPublic(verifiedBytes));


  ExtendedSigningKey.fromSeed(List<int> seed): this.fromVerifiedBytes(_seedToSecret(seed));
  ExtendedSigningKey.generate(): this.fromSeed(TweetNaCl.randombytes(TweetNaCl.seedSize));

  static List<int> _seedToSecret(List<int> seed) {
    final extendedSecret = Hash.sha512(seed);
    return setBits(extendedSecret);
  }

  static VerifyKey _toPublic(List<int> secret) {
    var pk = Uint8List(TweetNaCl.publicKeyLength);
    TweetNaClExt.scalar_base(pk, Uint8List.fromList(secret));
    return VerifyKey(pk);
  }

  static const extendedKeySize = 64;

  // prefixLength is a late binding variable.
  @override
  final int prefixLength = keyLength;

  static const keyLength = 64;

  ByteList get keyBytes => prefix;

  //late final VerifyKey _verifyKey;

  @override
  VerifyKey get publicKey => super.verifyKey;

  static bool isValidBits(List<int> bytes) {
    return ((bytes[0] & 7) == 0) &
        ((bytes[31] & 192) == 64);
  }

  static List<int> setBits(List<int> bytes) {
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
