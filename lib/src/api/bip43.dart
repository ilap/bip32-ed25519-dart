part of '../../api.dart';

///
/// `m / purpose' / *`
/// Reference: [BIP-0043](https://github.com/bitcoin/bips/blob/master/bip-0043.mediawiki)
///
abstract class Bip43KeyTree implements Bip32KeyTree {
  /// Purpose, defaults to Bip43 i.e. 43'
  int get purpose => Bip32KeyTree.hardenedIndex | 43;
}
