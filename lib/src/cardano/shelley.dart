import 'dart:typed_data';

import 'package:pinenacl/key_derivation.dart';

import 'package:bip32_ed25519/api.dart';
import 'package:bip32_ed25519/bip32_ed25519.dart';

class CardanoKeyIcarus extends Bip32Ed25519 {
  CardanoKeyIcarus(Uint8List masterSecret) : super(masterSecret);
  CardanoKeyIcarus.seed(String seed) : super.seed(seed);
  CardanoKeyIcarus.import(String key) : super.import(key);

  @override
  Bip32Key master(Uint8List seed) {
    final rawMaster = PBKDF2.hmac_sha512(Uint8List(0), seed, 4096, 96);

    return Bip32SigningKey.normalizeBytes(rawMaster);
  }

  @override
  Bip32Key doImport(String key) {
    // First we try the verify key as it's very cheap computitonaly.
    try {
      return Bip32VerifyKey.decode(key);
    } catch (e) {
      return Bip32SigningKey.decode(key);
    }
  }
}

void main() {
  final hex = HexCoder.instance;
  //final masterXprv =
  //    'ed25519bip32_sk1drm35zt6mrym4mg8nqcnyvaju6j40gzf8efn6j3elxztpv2fx4ync2a7ed862ew334g3vns0730578z690399j5mfyu3gzhl8a6n38ulpqtv4efsvk55s0qusjjllcet6nu7wuvvklk76qfvn0ceah7cfuqhjp9f';
  //final masterXpub =
  //    'ed25519bip32_pk1zddat8qcwxm4gqlawnrvdtec3l20r59pep60e0dzgf5p6ykrnsde7zqketjnqedffq7pep99ll3jh48euaccedlda5qjexl3nm0asnccqnsa2';
  // only accepts `ed25519bip32_sk` or `ed25519bip32_pk`

  final icarusKeyTree =
      CardanoKeyIcarus.seed('46e62370a138a182a498b8e2885bc032379ddf38');

  final addressKey = icarusKeyTree.forPath("m/1852'/1815'/0'/0/0");
  final accountKey = icarusKeyTree.forPath("m/1852'/1815'/0'");

  final importedKeyTree = CardanoKeyIcarus.import(accountKey.encode());
  final neutered =
      icarusKeyTree.neuterPriv(importedKeyTree.root as Bip32PrivateKey);

  final neuteredKeyTree = CardanoKeyIcarus.import(neutered.encode());

  // The m/1825'/1815'/0'/0/0 address and the M/0/0 must be the same.
  final neuteredAddress = neuteredKeyTree.forPath('M/0/0');

  assert(neuteredAddress == addressKey.publicKey);

  print(neuteredAddress.encode(Bech32Coder(hrp: 'xprv')));
}
