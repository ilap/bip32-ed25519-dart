import 'dart:async';
import 'accounts.dart';

import 'package:bip32_ed25519/api.dart';
import 'package:bip32_ed25519/bip32_ed25519.dart';

class Coin {
  Coin(this.chain, this.index);

  final Bip32Ed25519 chain;
  final int index;

  String get path => "m/1852'/1815'";

  Future<List<Account>> accounts() async {
    var accounts = <Account>[];

    var next = Account(this, 0x80000000, 0);
    while (await next.isUsed) {
      accounts.add(next);
      next = next.next();
    }

    return accounts;
  }
}
