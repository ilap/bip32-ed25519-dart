part of '../../../api.dart';

///
/// Using 1852' as the purpose field, we defined the following derivation path
/// `m / purpose' / coin_type' / account' / role / index`
/// Reference: [CIP-1852](https://github.com/cardano-foundation/CIPs/blob/master/CIP-1852/CIP-1852.md)
///
abstract class Cip1852KeyTree extends Bip44KeyTree {
  /// Staking Key	2 See CIP-0011
  static final int stakingKey = 2;

  /// DRep Key 3 See CIP-0105
  static final int drepKey = 3;

  /// Constitutional Committee Cold Key	4	See CIP-0105
  static final int ccColdKey = 4;

  /// Constitutional Committee Hot Key	5	See CIP-0105
  static final int ccHotKey = 5;

  // Change is renamed to role.
  int get role => change;
  set role(int newRole) => change;

  @override
  int get purpose => Bip32KeyTree.hardenedIndex | 1852;
}
