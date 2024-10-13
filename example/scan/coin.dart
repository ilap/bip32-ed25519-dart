import 'dart:async';

import 'package:bip32_ed25519/api.dart';
import 'package:bip32_ed25519/bip32_ed25519.dart';

import 'account.dart';

class Coin {
  Coin(this.chain, this.index);

  final Bip32Ed25519 chain;
  final int index;

  String get path => "m/1852'/${Bip32KeyTree.indexToPathNotation(index)}";

  Future<List<Account>> accounts() async {
    final accounts = <Account>[];

    var next = Account(this, Bip32KeyTree.hardenedIndex, 0);
    while (await next.isUsed) {
      accounts.add(next);
      next = next.next();
    }

    return accounts;
  }
}
