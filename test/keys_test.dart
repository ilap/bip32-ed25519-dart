import 'package:test/test.dart';
import 'package:bip32_ed25519/api.dart';

void main() {
  //const mnemonic =
  //    "art forum devote street sure rather head chuckle guard poverty release quote oak craft enemy";

  const entropy = [
    0x0c,
    0xcb,
    0x74,
    0xf3,
    0x6b,
    0x7d,
    0xa1,
    0x64,
    0x9a,
    0x81,
    0x44,
    0x67,
    0x55,
    0x22,
    0xd4,
    0xd8,
    0x09,
    0x7c,
    0x64,
    0x12
  ]; // 20
  const XPrv =
      'xprv1hretan5mml3tq2p0twkhq4tz4jvka7m2l94kfr6yghkyfar6m9wppc7h9unw6p65y23kakzct3695rs32z7vaw3r2lg9scmfj8ec5du3ufydu5yuquxcz24jlkjhsc9vsa4ufzge9s00fn398svhacse5su2awrw';
  const XPub =
      'xpub1eamrnx3pph58yr5l4z2wghjpu2dt2f0rp0zq9qquqa39p52ct0xercjgmegfcpcdsy4t9ld90ps2epmtcjy3jtq77n8z20qe0m3pnfqntgrgj';
  const secretKey =
      'b8f2bece9bdfe2b0282f5bad705562ac996efb6af96b648f4445ec44f47ad95c10e3d72f26ed075422a36ed8585c745a0e1150bcceba2357d058636991f38a3791e248de509c070d812ab2fda57860ac876bc489192c1ef4ce253c197ee219a4';
  const publicKey =
      'cf76399a210de8720e9fa894e45e41e29ab525e30bc402801c076250d1585bcd91e248de509c070d812ab2fda57860ac876bc489192c1ef4ce253c197ee219a4';
  const chainCode =
      '91e248de509c070d812ab2fda57860ac876bc489192c1ef4ce253c197ee219a4';
  const extendedSk =
      'ed25519e_sk1vz4jdwnehsx39zdj6c5n5c9q7r0gp77naw0226m7452ahvckxdvy6tfkllwl8fhpg5mt2akwkc7su4xy26ysn5qfy9jfne5uqfueljsqvy4us';
  const extendedPk =
      'ed25519_pk1wh6mye86aypjy0qlgndszk9txf8aw802wmct3xmm9yh935jhcukq60sp6l';
  group('Digital Signatures #1', () {
    group('Extended Key', () {
      test('Extendedtestvectors', () {
        var esk = ExtendedSigningKey.decode(extendedSk);
        var evk = VerifyKey.decode(extendedPk);
        var evk1 = esk.verifyKey;

        assert(evk == evk1);

        final messageBytes =
            'Nothing more threatening than the truth.'.codeUnits;
        final signedMessage = esk.sign(messageBytes);
        assert(evk.verifySignedMessage(signedMessage: signedMessage) == true);
        assert(evk.verify(
                signature: signedMessage.signature, message: messageBytes) ==
            true);
      });
    });

    group('Bip32 Key', () {
      test('Extended Bip32 testvectors', () {
        var esk = Bip32SigningKey.decode(XPrv);
        var evk = Bip32VerifyKey.decode(XPub);
        var evk1 = esk.verifyKey;

        assert(evk == evk1);

        final messageBytes =
            'Nothing more threatening than the truth.'.codeUnits;
        final signedMessage = esk.sign(messageBytes);
        assert(evk.verifySignedMessage(signedMessage: signedMessage) == true);
        assert(evk.verify(
                signature: signedMessage.signature, message: messageBytes) ==
            true);
      });
    });
  });
}
