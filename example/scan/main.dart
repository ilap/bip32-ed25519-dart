// ignore_for_file: constant_identifier_names

import 'package:bip32_ed25519/cardano.dart';
import 'package:bip39/bip39.dart' as bip39;
import 'coin.dart';

Future<void> main() async {
  const mnemonic =
      'test test test test test test test test test test test test test test test test test test test test test test test sauce';
  print('Generating Icarus master key from phrase:\n$mnemonic');

  final entropy = bip39.mnemonicToEntropy(mnemonic);
  final icarusKeyTree = CardanoIcarusKey.seed(entropy);
  final coin = Coin(icarusKeyTree, Bip32KeyTree.hardenedIndex | 1815);

  final accounts = await coin.accounts();
  accounts.forEach(print);
}
