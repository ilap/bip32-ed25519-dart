import 'dart:io';
import 'dart:convert';

import 'package:test/test.dart';
import 'package:bip32_ed25519/api.dart';

void main() {
  const xprvCoder = Bech32Coder(hrp: 'xprv');
  const xpubCoder = Bech32Coder(hrp: 'xpub');
  group('Key derivation tests', () {
    final dir = Directory.current;
    final file = File('${dir.path}/test/data/yoroi_keys.json');

    final contents = file.readAsStringSync();
    final dynamic yoroi = JsonDecoder().convert(contents);

    final dynamic keypairs = yoroi['keypairs'];

    final ck = yoroi['chain_prv']! as String;
    final cK = yoroi['chain_pub']! as String;

    final chainPrv = Bip32SigningKey.decode(ck, coder: xprvCoder);
    final chainPub = Bip32VerifyKey.decode(cK, coder: xpubCoder);

    var idx = 0;
    keypairs.asMap().forEach((int index, dynamic keypair) {
      var description = 'yoroi\'s m/1852\'/1815\'/0\'/0/$index';

      test(description, () {
        final xprv = keypair['xprv']! as String;
        final xpub = keypair['xpub']! as String;

        final k = Bip32SigningKey.decode(xprv, coder: xprvCoder);
        final K = Bip32VerifyKey.decode(xpub, coder: xpubCoder);

        final derivedPrv = chainPrv.derive(idx);
        final derivedPub = chainPub.derive(idx);
        assert(k == derivedPrv);
        assert(K == derivedPub);
        idx++;
      });
    });

    test('keytree depth exceeded', () {
      final exceededKey = Bip32SigningKey.normalizeBytes(Uint8List(96),
          depth: Bip32Ed25519.maxDepth);

      expect(
          () => exceededKey.derive(idx),
          throwsA(
              TypeMatcher<MaxDepthExceededBip23Ed25519DerivationKeyError>()));

      final singingKey = Bip32SigningKey.normalizeBytes(Uint8List(96),
          depth: Bip32Ed25519.maxDepth - 1);

      final derivedKey = singingKey.derive(idx);

      assert(derivedKey.depth == Bip32Ed25519.maxDepth);
      expect(
          () => derivedKey.derive(idx),
          throwsA(
              TypeMatcher<MaxDepthExceededBip23Ed25519DerivationKeyError>()));
    });
  });
}
