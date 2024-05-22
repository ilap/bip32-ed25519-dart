part of '../../api.dart';

///
/// `m / purpose' / coin_type' / account' / change / address_index`
/// Reference: [BIP-0044](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki)
///
abstract class Bip44KeyTree implements Bip43KeyTree {
  /// Purpose, defaults to Bip44 i.e. 44'
  @override
  int get purpose => Bip32KeyTree.hardenedIndex | 44;

  /// Coin Type, defaults to 0' the Bitcoin. Not used in Cardano
  int get coinType => Bip32KeyTree.hardenedIndex;

  /// Account,  defaults to 0' the first account index
  int get account => Bip32KeyTree.hardenedIndex;

  static final int external = 0;
  static final int internal = 1;

  /// Change, defaults to the external keys
  int get change => external;

  /// Address Index, defaults to the first address key
  final int addressIndex = 0;
}
