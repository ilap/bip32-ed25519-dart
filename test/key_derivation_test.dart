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

      final dynamic ak = yoroi['account_prv'] !as String;
      final dynamic aK = yoroi['account_pub'] !as String;

      final derivator = Bip32Ed25519KeyDerivation.instance;
      final accountPrv = Bip32SigningKey.decode(ak, coder: xprvCoder);
      final accountPub = Bip32VerifyKey.decode(aK, coder: xpubCoder);

      var idx = 0;
      keypairs.asMap().forEach((index, dynamic keypair) {
        var description = 'yoroi\'s m/1852\'/1815\'/0\'/0/$index';

        test(description, () {
          final xprv = keypair['xprv']! as String;
          final xpub = keypair['xpub']! as String;

          final k = Bip32SigningKey.decode(xprv, coder: xprvCoder);
          final K = Bip32VerifyKey.decode(xpub, coder: xpubCoder);

          final derivedPrv = derivator.ckdPriv(accountPrv, idx);
          final derivedPub = derivator.ckdPub(accountPub, idx);
          assert(k == derivedPrv);
          assert(K == derivedPub);
          idx++;
        });
      });
    });
}
