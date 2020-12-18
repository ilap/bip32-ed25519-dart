import 'dart:typed_data';
import 'package:pinenacl/api.dart';

mixin ExtendedKey {
  ExtendedKey get public;
  //ByteList get chainCode;
  //ExtendedKey derive(int index);
}

mixin Bip32 {
  ExtendedKey get master;
  ExtendedKey derive(int index);
  ExtendedKey fromPath(String path);
}

mixin ExtendedPrivateKey implements ExtendedKey {}

mixin ExtendedPublicKey implements ExtendedKey {}

// This is a simple ED25519 Public Key.
class ExtendedShelleyVerifyKey extends VerifyKey
    with ExtendedPublicKey
    implements Verify {
  ExtendedShelleyVerifyKey(List<int> list) : super(list);

  factory ExtendedShelleyVerifyKey.decode(String data,
      {Encoder coder = VerifyKey.decoder}) {
    final decoded = coder.decode(data);
    return ExtendedShelleyVerifyKey(decoded);
  }

  @override
  ExtendedKey get public => this;
}

class ExtendedShelleySigningKey extends ByteList
    implements AsymmetricPrivateKey, Sign {
  ExtendedShelleySigningKey._fromValidBytes(List<int> secret)
      : verifyKey = _toPublic(secret),
        super(secret);

  static ExtendedShelleyVerifyKey _toPublic(List<int> validBytes) {
    if (validBytes is! Uint8List) {
      validBytes = Uint8List.fromList(validBytes);
    }

    final pub = Uint8List(TweetNaCl.publicKeyLength);
    TweetNaClExt.scalar_base(pub, validBytes.sublist(0, 32));

    return ExtendedShelleyVerifyKey(pub);
  }

  factory ExtendedShelleySigningKey.decode(String data,
      [Encoder defaultDecoder = decoder]) {
    final decoded = defaultDecoder.decode(data);
    return ExtendedShelleySigningKey._fromValidBytes(decoded);
  }

  static const decoder = Bech32Coder(hrp: 'ed25519e_sk');

  @override
  Encoder get encoder => decoder;

  @override
  AsymmetricPublicKey get publicKey => verifyKey;

  @override
  final ExtendedShelleyVerifyKey verifyKey;

  @override
  SignedMessage sign(List<int> message) {
    // signed message
    var sm = Uint8List(message.length + TweetNaCl.signatureLength);
    final result = TweetNaCl.crypto_sign(
        sm, -1, Uint8List.fromList(message), 0, message.length, this);
    if (result != 0) {
      throw Exception('Signing the massage is failed');
    }

    return SignedMessage.fromList(signedMessage: sm);
  }

  ExtendedKey get public => verifyKey;
}

void main() {
  var esk = ExtendedShelleySigningKey.decode(
      'ed25519e_sk1vz4jdwnehsx39zdj6c5n5c9q7r0gp77naw0226m7452ahvckxdvy6tfkllwl8fhpg5mt2akwkc7su4xy26ysn5qfy9jfne5uqfueljsqvy4us');
  var epk = ExtendedShelleyVerifyKey.decode(
      'ed25519_pk1wh6mye86aypjy0qlgndszk9txf8aw802wmct3xmm9yh935jhcukq60sp6l');

  print(esk.encode(HexCoder.instance));

  var epk1 = esk.publicKey;
  print(epk.encode());
  print(epk1.encode());
}
