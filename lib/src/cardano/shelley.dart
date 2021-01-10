import 'dart:typed_data';

import 'package:bip32_ed25519/api.dart';

class CardanoKeyTree extends Bip32KeyTree  {
  CardanoKeyTree.seed(String seed) : super.seed(seed);
  CardanoKeyTree.import(String key) : super.import(key);

  @override
  Bip32Key master(Uint8List seed) {
    return Bip32SigningKey.fromVerifiedBytes(seed);
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
