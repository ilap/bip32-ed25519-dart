import 'dart:async';

import 'package:bip32_ed25519/api.dart';
import 'package:bip32_ed25519/bip32_ed25519.dart';

import 'coin.dart';
import 'scanner.dart';
import 'address.dart';

class Account {
  Account(this.coin, this.index, this.change);

  final Coin coin;
  final int index;
  final int change;

  String get path =>
      '${coin.path}/${Bip32KeyTree.indexToPathNotation(index)}/$change';
  Bip32Ed25519 get chain => coin.chain;
  Future<bool> get isUsed async {
    return (await nextUnusedAddress()).index != 0;
  }

  Future<Address> nextUnusedAddress() async {
    final used = await usedAddresses();

    if (used.isEmpty) {
      return Address(this, 0);
    }

    return Address(this, used.last.index + 1);
  }

  Future<List<Address>> usedAddresses() async {
    final usedAddresses = <Address>[];

    var addressIndex = 0;
    var nextAddress = Address(this, addressIndex);

    while (await scanners[0].present(nextAddress.toBaseAddress)) {
      usedAddresses.add(nextAddress);
      addressIndex++;
      nextAddress = Address(this, addressIndex);
    }

    return usedAddresses;
  }

  Account next() {
    return Account(coin, index + 1, 0);
  }

  @override
  String toString() {
    return '''Account(${coin.path}/${Bip32KeyTree.indexToPathNotation(index)}'''
        '''/${Bip32KeyTree.indexToPathNotation(change)})''';
  }
}
