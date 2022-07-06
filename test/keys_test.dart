import 'package:test/test.dart';

import 'package:bip32_ed25519/api.dart';

void main() {
  const xprvCoder = Bech32Coder(hrp: 'xprv');
  const xpubCoder = Bech32Coder(hrp: 'xpub');

  //const mnemonic =
  //    "art forum devote street sure rather head chuckle guard poverty release quote oak craft enemy";
  // const entropy = [0x0c, 0xcb, 0x74, 0xf3, 0x6b, 0x7d, 0xa1, 0x64, 0x9a, 0x81, 0x44, 0x67,  0x55, 0x22, 0xd4, 0xd8, 0x09, 0x7c, 0x64,    0x12  ]; // 20
  const xPrv =
      'xprv1hretan5mml3tq2p0twkhq4tz4jvka7m2l94kfr6yghkyfar6m9wppc7h9unw6p65y23kakzct3695rs32z7vaw3r2lg9scmfj8ec5du3ufydu5yuquxcz24jlkjhsc9vsa4ufzge9s00fn398svhacse5su2awrw';
  const xPub =
      'xpub1eamrnx3pph58yr5l4z2wghjpu2dt2f0rp0zq9qquqa39p52ct0xercjgmegfcpcdsy4t9ld90ps2epmtcjy3jtq77n8z20qe0m3pnfqntgrgj';
  //const secretBytesHex =
  //    'b8f2bece9bdfe2b0282f5bad705562ac996efb6af96b648f4445ec44f47ad95c10e3d72f26ed075422a36ed8585c745a0e1150bcceba2357d058636991f38a3791e248de509c070d812ab2fda57860ac876bc489192c1ef4ce253c197ee219a4';
  const publicBytesHex =
      'cf76399a210de8720e9fa894e45e41e29ab525e30bc402801c076250d1585bcd91e248de509c070d812ab2fda57860ac876bc489192c1ef4ce253c197ee219a4';
  //const chainCode =
  //    '91e248de509c070d812ab2fda57860ac876bc489192c1ef4ce253c197ee219a4';
  const extendedSk =
      'ed25519e_sk1vz4jdwnehsx39zdj6c5n5c9q7r0gp77naw0226m7452ahvckxdvy6tfkllwl8fhpg5mt2akwkc7su4xy26ysn5qfy9jfne5uqfueljsqvy4us';
  const extendedPk =
      'ed25519_pk1wh6mye86aypjy0qlgndszk9txf8aw802wmct3xmm9yh935jhcukq60sp6l';

  final _0 = Uint8List(0);
  final _32 = Uint8List(32);
  final _63 = Uint8List(63);
  final _64 = Uint8List(64);
  final _96 = Uint8List(96);

  void doSigningTest(Sign sk, Verify vk) {
    final vk1 = sk.verifyKey;
    assert(vk == vk1);

    final messageBytes = Uint8List.fromList(
        'Nothing more threatening than the truth.'.codeUnits);
    final signedMessage = sk.sign(messageBytes);
    assert(vk.verifySignedMessage(signedMessage: signedMessage) == true);
    assert(
        vk.verify(signature: signedMessage.signature, message: messageBytes) ==
            true);
  }

  group('Key test vectors', () {
    test('Extended key testvectors', () {
      var esk = ExtendedSigningKey.decode(extendedSk);
      var evk = VerifyKey.decode(extendedPk);
      doSigningTest(esk, evk);
    });

    test('Bip32 key testvectors', () {
      var xprv = Bip32SigningKey.decode(xPrv, coder: xprvCoder);
      var xpub = Bip32VerifyKey.decode(xPub, coder: xpubCoder);
      doSigningTest(xprv, xpub);
    });
  });

  group('Key constructors', () {
    test('Extended key constructors', () {
      final ed25519e_sk = ExtendedSigningKey.generate();

      expect(() => ExtendedSigningKey, returnsNormally);
      expect(() => ExtendedSigningKey(ed25519e_sk.asTypedList),
          returnsNormally); // From valid key

      expect(() => ExtendedSigningKey.generate(), returnsNormally);
      expect(() => ExtendedSigningKey.fromSeed(_32), returnsNormally);

      expect(() => ExtendedSigningKey.normalizeBytes(_64.toUint8List()),
          returnsNormally);

      expect(() => ExtendedSigningKey.fromValidBytes(ed25519e_sk.asTypedList),
          returnsNormally);

      expect(() => ExtendedSigningKey.decode(extendedSk), returnsNormally);

      // Throws errors or exceptions as the 2nd bit is not set
      expect(() => ExtendedSigningKey(_64),
          throwsA(TypeMatcher<InvalidSigningKeyError>()));
      expect(
          () => ExtendedSigningKey(_63), throwsA(predicate((e) => e is Error)));
      expect(() => ExtendedSigningKey.fromSeed(_63), throwsException);

      expect(() => ExtendedSigningKey.fromValidBytes(_64),
          throwsA(TypeMatcher<InvalidSigningKeyError>()));

      expect(() => ExtendedSigningKey.decode(extendedPk), throwsException);

      // Every 32-byte long bytes are valid public key
      expect(() => VerifyKey(_0), throwsException);
      expect(() => VerifyKey(_32), returnsNormally);
      expect(() => VerifyKey(_63), throwsException);
      expect(() => VerifyKey(_64), throwsException);

      // expect(() => ExtendedSigningKey(), throwsA(predicate((e) => e is ArgumentError && e.message == 'Error')));
      // expect(() => ExtendedSigningKey(), throwsA(allOf(isArgumentError, predicate((e) => e.message == 'Error'))));
    });
    test('Bip32-Ed25519 key constructors', () {
      final xprv = Bip32SigningKey.decode(xPrv, coder: xprvCoder);
      final chainCode = xprv.chainCode;

      final pubBytes = HexCoder.instance.decode(publicBytesHex).sublist(0, 32);
      final xpub = Bip32VerifyKey.fromKeyBytes(pubBytes, chainCode.asTypedList);

      assert(xpub == xprv.verifyKey);

      expect(() => Bip32SigningKey, returnsNormally);
      expect(() => Bip32SigningKey(xprv.asTypedList), returnsNormally);

      expect(() => Bip32SigningKey.generate(), returnsNormally);

      expect(() => Bip32SigningKey.normalizeBytes(_96), returnsNormally);

      expect(() => Bip32SigningKey.fromValidBytes(xprv.asTypedList),
          returnsNormally);

      expect(() => Bip32SigningKey.decode(xPrv, coder: xprvCoder),
          returnsNormally);

      // Throws errors or exceptions as the 2nd bit is not set
      expect(() => Bip32SigningKey(_32),
          throwsA(TypeMatcher<InvalidSigningKeyError>()));
      expect(() => Bip32SigningKey(_63),
          throwsA(TypeMatcher<InvalidSigningKeyError>()));
      expect(() => Bip32SigningKey(_96),
          throwsA(TypeMatcher<InvalidSigningKeyError>()));
      expect(() => Bip32SigningKey(_63), throwsA(predicate((e) => e is Error)));
      expect(() => ExtendedSigningKey.fromSeed(_63), throwsException);

      expect(() => Bip32SigningKey.fromValidBytes(_96),
          throwsA(TypeMatcher<InvalidSigningKeyError>()));

      expect(() => Bip32SigningKey.decode(extendedPk), throwsException);

      // Every 32-byte long bytes are valid public key
      expect(() => Bip32VerifyKey(_0), throwsException);
      expect(() => Bip32VerifyKey(_32), throwsException);
      expect(() => Bip32VerifyKey(_63), throwsException);
      expect(() => Bip32VerifyKey(_64), returnsNormally);
      expect(() => Bip32VerifyKey(_96), throwsException);
    });
  });
}
