import 'package:pinenacl/key_derivation.dart';

import 'package:bip32_ed25519/api.dart';
import 'package:bip32_ed25519/bip32_ed25519.dart';

class CardanoIcarusKey extends Bip32Ed25519 {
  CardanoIcarusKey(super.masterSecret);
  CardanoIcarusKey.seed(super.seed) : super.seed();
  CardanoIcarusKey.import(super.key) : super.import();

  @override
  Bip32Key master(Uint8List seed) {
    final rawMaster = PBKDF2.hmac_sha512(Uint8List(0), seed, 4096, 96);
    return Bip32SigningKey.normalizeBytes(rawMaster);
  }
}
