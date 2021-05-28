import 'dart:async';
import 'package:bip32_ed25519/api.dart';
import 'package:bip32_ed25519/bip32_ed25519.dart';
import 'coin.dart';
import 'scanner.dart';

import 'package:bip32_ed25519/bip32_ed25519.dart';
import 'package:pinenacl/ed25519.dart';
import 'package:pinenacl/digests.dart';
import 'package:pinenacl/tweetnacl.dart';
import 'package:bip32_ed25519/src/bip32_ed25519/ed25519_extended.dart';
import 'package:bip32_ed25519/api.dart';


/// https://github.com/input-output-hk/cardano-addresses
class Address {
  Address(this.account, this.index);

  final Account account;
  final int index;

  String get path => '${account.path}/$index';
  Bip32Ed25519 get chain => account.chain;


  // ignore: non_constant_identifier_names
  String get toBaseAddress {
      final pk = chain.forPath(path).publicKey.keyBytes;
      final a = Hash.blake2b(pk.asTypedList, digestSize: 28);

      const coder = Bech32Coder(hrp:'addr_test');
      final addr = ByteList([0x60]+a).encode(coder);

      print('Address: $addr');
      return addr;
  }
}

class Account {
  Account(this.coin, this.index, this.change);

  final Coin coin;
  final int index;
  final int change;

  String get path => '${coin.path}/$index/$change';
  Bip32Ed25519 get chain => coin.chain;
  Future<bool> get isUsed async {
    return (await nextUnusedAddress()).index != 0;
  }

  Future<Address> nextUnusedAddress() async {
    var used = await usedAddresses();

    if (used.isEmpty) {
      return Address(this, 0);
    }

    return Address(this, used.last.index + 1);
  }

  Future<List<Address>> usedAddresses() async {
    var usedAddresses = <Address>[];

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
}