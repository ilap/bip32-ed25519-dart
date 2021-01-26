import 'package:bip32_ed25519/cardano.dart';

void main() {
  const seed =
      '475083b81730de275969b1f18db34b7fb4ef79c66aa8efdd7742f1bcfe204097';
  const accountPath = "m/1852'/1815'/0'";
  const addressPath = "m/1852'/1815'/0'/0/0";
  const neuteredPath = 'M/0/0';
  const nonNeuteredPath = 'm/0/0';
  print('Generating Icarus master key from seed: $seed');

  final icarusKeyTree = CardanoKeyIcarus.seed(seed);

  print(icarusKeyTree.root.encode(Bech32Coder(hrp: 'xprv')));
  print('');
  print('Generating account key pair from path $accountPath');

  final accountKey = icarusKeyTree.forPath(accountPath);

  print(accountKey.encode(Bech32Coder(hrp: 'xprv')));
  print(accountKey.publicKey.encode(Bech32Coder(hrp: 'xpub')));
  print('');

  print('Importing account key to a KeyTree: $accountPath -> m/');
  final importedKeyTree = CardanoKeyIcarus.import(accountKey.encode());

  print('Importing account\'s public to a KeyTree: M/');
  // It could be imported straight from the public key
  // but trying the neutered feature.
  final neutered =
      icarusKeyTree.neuterPriv(importedKeyTree.root as Bip32PrivateKey);

  final neuteredKeyTree = CardanoKeyIcarus.import(neutered.encode());

  print(neuteredKeyTree.root.encode(Bech32Coder(hrp: 'xpub')));
  print('');

  print('These three public address keys must be the same...\n');
  print('Generating address public key from ${addressPath}');
  final addressKey = icarusKeyTree.forPath(addressPath);
  print(addressKey.publicKey.encode(Bech32Coder(hrp: 'xpub')));

  print('');

  print('Generating address public key from ${neuteredPath}');
  final neuteredAddress = neuteredKeyTree.forPath(neuteredPath);
  print(neuteredAddress.encode(Bech32Coder(hrp: 'xpub')));

  print('');

  print('Generating address public key from ${nonNeuteredPath}');
  final addressKey1 = importedKeyTree.forPath(nonNeuteredPath);
  print(addressKey1.publicKey.encode(Bech32Coder(hrp: 'xpub')));

  print('');

  // The m/1825'/1815'/0'/0/0 address and the M/0/0 must be the same.

  assert(neuteredAddress == addressKey.publicKey);
  assert(addressKey1.publicKey == addressKey.publicKey);
}
