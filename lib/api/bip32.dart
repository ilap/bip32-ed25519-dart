part of bip32_ed25519.api;

class ChainCode extends ByteList {
  ChainCode(Uint8List bytes) : super(bytes, chainCodeLength);
  static const int chainCodeLength = 32;
}

mixin Bip32Key on AsymmetricKey {
  ChainCode get chainCode;
  ByteList get keyBytes;

  Bip32Key derive(int index);
}

mixin Bip32PrivateKey on AsymmetricPrivateKey implements Bip32Key {
  Bip32PrivateKey master(Uint8List seed);
  ByteList get keyBytes => prefix;
}

mixin Bip32PublicKey on AsymmetricPublicKey implements Bip32Key {
  ByteList get keyBytes => prefix;
}

abstract class Bip32ChildKeyDerivaton {
  /// Private parent key to private child key
  Bip32PrivateKey ckdPriv(Bip32PrivateKey parentSecret, int index);

  /// Public parent key to public child key
  Bip32PublicKey ckdPub(Bip32PublicKey parentSecret, int index);

  /// Private parent key to public Child key
  Bip32PublicKey neuterPriv(Bip32PrivateKey parentSecret, int index);

  /// Public parent key to private child key
  /// It is imposibble
  
  /// Master key Derivation
  Bip32PrivateKey master(Uint8List masterSecret);
}

abstract class Bip32KeyTree {
  Bip32KeyTree.seed(String seed) {
    this.root = master(HexCoder.instance.decode(seed));
  }

  Bip32KeyTree.import(String key) {
    this.root = doImport(key);
  }

  late final Bip32Key root;

  static const int hardenedIndex = 0x80000000;
  static const String _hardenedSuffix = "'";
  static const String _privateKeyPrefix = 'm';
  static const String _publicKeyPrefix = 'M';

  bool get isPrivate => root is Bip32PrivateKey;

  Bip32Key master(Uint8List seed);
  Bip32Key doImport(String key);

  Bip32Key forPath(String path) {
    _validatePath(path);

    final wantsPrivate = path[0] == _privateKeyPrefix;
    final children = _parseChildren(path);

    if (children.isEmpty) {
      if (wantsPrivate) {
        return root;
      }
      return root.publicKey as Bip32Key;
    }

    return children.fold(root, (previousKey, childNumber) {
      return previousKey.derive(childNumber);
    });
  }

  void _validatePath(String path) {
    var kind = path.split('/').removeAt(0);

    if (![_privateKeyPrefix, _publicKeyPrefix].contains(kind)) {
      throw Exception("Path needs to start with 'm' or 'M'");
    }

    if (kind == _privateKeyPrefix && root is Bip32PublicKey) {
      throw Exception('Cannot derive private key from public master');
    }
  }

  Iterable<int> _parseChildren(String path) {
    var explodedList = path.split('/')
      ..removeAt(0)
      ..removeWhere((child) => child == '');

    return explodedList.map((pathFragment) {
      if (pathFragment.endsWith(_hardenedSuffix)) {
        pathFragment = pathFragment.substring(0, pathFragment.length - 1);
        return int.parse(pathFragment) + hardenedIndex;
      } else {
        return int.parse(pathFragment);
      }
    });
  }
}
