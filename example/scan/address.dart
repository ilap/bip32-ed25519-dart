import 'package:bip32_ed25519/api.dart';
import 'package:bip32_ed25519/bip32_ed25519.dart';

import 'account.dart';

/// https://github.com/input-output-hk/cardano-addresses
class Address {
  Address(this.account, this.index);

  final Account account;
  final int index;

  String get path =>
      '${account.path}/${Bip32KeyTree.indexToPathNotation(index)}';

  String get stakePath =>
      '${account.coin.path}/${Bip32KeyTree.indexToPathNotation(account.index)}/2/0';
  Bip32Ed25519 get chain => account.chain;

  // ignore: non_constant_identifier_names
  String get toBaseAddress {
    final pk = chain.pathToKey(path).publicKey as Bip32Key;
    final paymentPart = Hash.blake2b(pk.rawKey.asTypedList, digestSize: 28);

    final spk = chain.pathToKey(stakePath).publicKey as Bip32Key;
    final stakePart = Hash.blake2b(spk.rawKey.asTypedList, digestSize: 28);

    const coder = Bech32Encoder(hrp: 'addr_test');
    final addr = ByteList([0x00] + paymentPart + stakePart).encode(coder);

    print('Address: $addr');
    return addr;
  }
}
