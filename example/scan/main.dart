// ignore_for_file: constant_identifier_names

import 'package:bip32_ed25519/cardano.dart';

import 'coin.dart';

void main() {
  // const phrase = 'exercise club noble adult miracle awkward problem olympic puppy private goddess piano fatal fashion vacuum';
  // print('Generating Icarus master key from phrase:\n$phrase');
  const root_xsk =
      'root_xsk1hqzfzrgskgnpwskxxrv5khs7ess82ecy8za9l5ef7e0afd2849p3zryje8chk39nxtva0sww5me3pzkej4rvd5cae3q3v8eu7556n6pdrp4fdu8nsglynpmcppxxvfdyzdz5gfq3fefjepxhvqspmuyvmvqg8983';

  final icarusKeyTree = CardanoIcarusKey.import(root_xsk);
  final coin = Coin(icarusKeyTree, 0);
  print('Coind : ${coin.path} ${coin.accounts()}');
}
