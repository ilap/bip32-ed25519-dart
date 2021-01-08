import 'dart:typed_data';
import 'package:pinenacl/api.dart';

mixin ExtendedKey on Suffix {
  ExtendedKey get public;
  ByteList get key => prefix;
}

mixin Bip32 on Suffix {
  ByteList get chainCode => suffix;
  ExtendedKey get master;
  ExtendedKey fromPath(String path);
  ExtendedKey derive(int index);
}

mixin ExtendedPrivateKey implements ExtendedKey {}

mixin ExtendedPublicKey implements ExtendedKey {}

abstract class ChainCode {}

// This is a simple ED25519 Public Key.
class CardanoExtendedPublicKey extends VerifyKey implements Verify {
  CardanoExtendedPublicKey(List<int> list) : super(list);

  factory CardanoExtendedPublicKey.decode(String data,
      {Encoder coder = VerifyKey.decoder}) {
    final decoded = coder.decode(data);
    return CardanoExtendedPublicKey(decoded);
  }
}

class CardanoExtendedPrivateKey extends ByteList
    with Suffix
    implements AsymmetricPrivateKey, Sign {
  CardanoExtendedPrivateKey._fromValidBytes(List<int> secret)
      : verifyKey = _toPublic(secret),
        super(secret);

  static CardanoExtendedPublicKey _toPublic(List<int> validBytes) {
    if (validBytes is! Uint8List) {
      validBytes = Uint8List.fromList(validBytes);
    }

    final pub = Uint8List(TweetNaCl.publicKeyLength);
    TweetNaClExt.scalar_base(pub, validBytes.sublist(0, 32));

    return CardanoExtendedPublicKey(pub);
  }

  factory CardanoExtendedPrivateKey.decode(String data,
      [Encoder defaultDecoder = decoder]) {
    final decoded = defaultDecoder.decode(data);
    return CardanoExtendedPrivateKey._fromValidBytes(decoded);
  }

  static const decoder = Bech32Coder(hrp: 'ed25519e_sk');

  @override
  Encoder get encoder => decoder;

  @override
  AsymmetricPublicKey get publicKey => verifyKey;

  @override
  final CardanoExtendedPublicKey verifyKey;

  @override
  SignedMessage sign(List<int> message) {
    // signed message
    var sm = Uint8List(message.length + TweetNaCl.signatureLength);
    final result = TweetNaCl.crypto_sign(sm, -1, Uint8List.fromList(message), 0,
        message.length, Uint8List.fromList(this.prefix + verifyKey),
        extended: true);
    if (result != 0) {
      throw Exception('Signing the massage is failed');
    }

    return SignedMessage.fromList(signedMessage: sm);
  }

  @override
  int prefixLength = 64;
}

class CardanoBip32PublicKey extends CardanoExtendedPublicKey
    with Suffix
    implements ExtendedPublicKey {
  CardanoBip32PublicKey(List<int> list) : super(list);

  ExtendedKey get public => this;
  ByteList get chainCode => suffix;
  ExtendedKey derive(int index) {
    return CardanoBip32PublicKey([]);
  }

  factory CardanoBip32PublicKey.decode(String data, {Encoder coder = decoder}) {
    final decoded = coder.decode(data);
    return CardanoBip32PublicKey(decoded);
  }
  static const decoder = Bech32Coder(hrp: 'xpub');

  @override
  Encoder get encoder => decoder;

  @override
  int prefixLength = 32;

  @override
  ByteList get key => prefix;
}

class CardanoBip32PrivateKey extends CardanoExtendedPrivateKey
    with Suffix
    implements ExtendedPrivateKey {
  CardanoBip32PrivateKey(List<int> list) : super._fromValidBytes(list);
  ExtendedKey get public =>
      CardanoBip32PublicKey(this.publicKey + this.chainCode);
  ByteList get chainCode => suffix;
  ExtendedKey derive(int index) {
    return CardanoBip32PrivateKey([]);
  }

  factory CardanoBip32PrivateKey.decode(String data,
      [Encoder defaultDecoder = decoder]) {
    final decoded = defaultDecoder.decode(data);
    return CardanoBip32PrivateKey(decoded);
  }

  static const decoder = Bech32Coder(hrp: 'xprv');

  @override
  Encoder get encoder => decoder;

  @override
  int prefixLength = 64;

  @override
  ByteList get key => prefix;
}

void main() {
  // Test 1
  var esk = CardanoBip32PrivateKey.decode(
      'xprv1hretan5mml3tq2p0twkhq4tz4jvka7m2l94kfr6yghkyfar6m9wppc7h9unw6p65y23kakzct3695rs32z7vaw3r2lg9scmfj8ec5du3ufydu5yuquxcz24jlkjhsc9vsa4ufzge9s00fn398svhacse5su2awrw');
  //  'ed25519e_sk1vz4jdwnehsx39zdj6c5n5c9q7r0gp77naw0226m7452ahvckxdvy6tfkllwl8fhpg5mt2akwkc7su4xy26ysn5qfy9jfne5uqfueljsqvy4us');
  var epk = CardanoBip32PublicKey.decode(
      'xpub1eamrnx3pph58yr5l4z2wghjpu2dt2f0rp0zq9qquqa39p52ct0xercjgmegfcpcdsy4t9ld90ps2epmtcjy3jtq77n8z20qe0m3pnfqntgrgj');
  //  'ed25519_pk1wh6mye86aypjy0qlgndszk9txf8aw802wmct3xmm9yh935jhcukq60sp6l');

  print('AAAAAA: ' + esk.public.encode(HexCoder.instance));
  print('BBBBBB: ' + epk.encode(HexCoder.instance));
  //print('CCCCCC: ' + esk.public.chainCode.encode(HexCoder.instance));
  print('DDDDDD: ' + epk.chainCode.encode(HexCoder.instance));

  var message = 'Hello world!'.codeUnits;

  var signature = esk.sign(message);
  print(esk.encode(HexCoder.instance));

  print(signature.toString());
  print(epk.verifySignedMessage(signedMessage: signature));

  var epk1 = esk.publicKey;
  print(epk.encode());
  print(epk1.encode());

  // Test 2
  // mnemonic: art forum devote street sure rather head chuckle guard poverty release quote oak craft enemy
  // entropy: [0x0c, 0xcb, 0x74, 0xf3, 0x6b, 0x7d, 0xa1, 0x64, 0x9a, 0x81, 0x44, 0x67, 0x55, 0x22, 0xd4, 0xd8, 0x09, 0x7c, 0x64, 0x12];
  // xprv1hretan5mml3tq2p0twkhq4tz4jvka7m2l94kfr6yghkyfar6m9wppc7h9unw6p65y23kakzct3695rs32z7vaw3r2lg9scmfj8ec5du3ufydu5yuquxcz24jlkjhsc9vsa4ufzge9s00fn398svhacse5su2awrw
  // xpub1eamrnx3pph58yr5l4z2wghjpu2dt2f0rp0zq9qquqa39p52ct0xercjgmegfcpcdsy4t9ld90ps2epmtcjy3jtq77n8z20qe0m3pnfqntgrgj
  // sk: b8f2bece9bdfe2b0282f5bad705562ac996efb6af96b648f4445ec44f47ad95c10e3d72f26ed075422a36ed8585c745a0e1150bcceba2357d058636991f38a3791e248de509c070d812ab2fda57860ac876bc489192c1ef4ce253c197ee219a4
  // pk: cf76399a210de8720e9fa894e45e41e29ab525e30bc402801c076250d1585bcd91e248de509c070d812ab2fda57860ac876bc489192c1ef4ce253c197ee219a4
  // cc: 91e248de509c070d812ab2fda57860ac876bc489192c1ef4ce253c197ee219a4
}
