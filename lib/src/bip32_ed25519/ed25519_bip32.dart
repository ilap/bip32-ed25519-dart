// ignore_for_file: non_constant_identifier_names, no_leading_underscores_for_local_identifiers
import 'package:pinenacl/tweetnacl.dart';

import 'package:bip32_ed25519/api.dart';
import 'package:bip32_ed25519/bip32_ed25519.dart';

// Errors
class InvalidBip23Ed25519DerivationKeyError extends Error {}

class MaxDepthExceededBip23Ed25519DerivationKeyError extends Error {}

// Exceptions
class InvalidBip32Ed25519IndexException implements Exception {}

class InvalidBip32Ed25519MasterSecretException implements Exception {}

///
/// This is the dart implementation of the `BIP32-Ed25519 Hierarchical
/// Deterministic Keys over a Non-linear Key space` key derivation
/// algorithm.
class Bip32Ed25519 extends Bip32Ed25519KeyDerivation with Bip32KeyTree {
  /// It creates a BIP32-ED25519 specific key tree from a master seed.
  /// The master seed is an `n-bit` entropy, that can come from different
  /// sources. E.g. From some `bip-0039` tool, `CPRNG` etc.
  ///
  /// The root of the tree is a valid BIP32-ED25519 `master key`.
  Bip32Ed25519(Uint8List seed) {
    root = master(seed);
  }

  /// It creates a BIP32-ED25519 specific key tree from a hex string representation
  /// of the master seed, which is a hex string representation of an `n-bit` length entropy,
  /// that can come from different sources. E.g. From some `bip-0039` tool, `CPRNG` etc.
  ///
  /// The root of the tree is a valid BIP32-ED25519 `master key`.
  Bip32Ed25519.seed(String masterSeedHex) {
    root = master(Base16Encoder.instance.decode(masterSeedHex));
  }

  /// It creates a sub key tree from a, usually `Bech32`, decoded,
  /// `Bip32-Ed25519` compatible private or public key.
  ///
  /// It can be used for creating read-, watch-only HD wallets.
  ///
  /// The imported key becomes the root node of the sub tree.
  /// The root of the tree, usually, is **NOT** a `BIP32-ED25519` master key,
  /// but a valid `BIP-ED25519` compatible signing and verifying key.
  Bip32Ed25519.import(String encodedKey) {
    root = doImport(encodedKey);
  }

  /// It creates a sub key tree from an imported `BIP-ED25519` compatible
  /// private/signing or public/verifying key.
  ///
  /// It can be used for creating read-, watch-only HD wallets.
  ///
  /// The imported key becomes the root node of the sub tree.
  /// The root of the tree, usually, is **NOT** a `BIP32-ED25519` master key,
  /// but a valid `BIP-ED25519` compatible signing and verifying key.
  Bip32Ed25519.importFromKey(Bip32Key key) {
    root = key;
  }

  /// BIP32-ED25519 dependent tree depth.
  /// The maximum number of levels in the tree is 2^20 = 1048576.
  /// Tree datastructure's `level` =    `depth + 1`
  /// FIXME: BIP32-ED25519 specific depth check
  static final int maxDepth = 1048576 - 1;

  /// The default implementation of the original BIP32-ED25519's master key
  /// generation.
  @override
  Bip32Key master(Uint8List seed) {
    final secretBytes = Hash.sha512(seed);

    if ((secretBytes[31] & 0x20) != 0) {
      throw InvalidBip32Ed25519MasterSecretException();
    }

    final rootChainCode = Hash.sha256([0x01, ...seed].toUint8List());

    final rootKey = Bip32SigningKey.normalizeBytes(
        [...secretBytes, ...rootChainCode].toUint8List());

    PineNaClUtils.listZero(seed);
    PineNaClUtils.listZero(rootChainCode);

    return rootKey;
  }

  @override
  Bip32Key doImport(String key) {
    try {
      return Bip32VerifyKey.decode(key);
    } catch (e) {
      return Bip32SigningKey.decode(key);
    }
  }
}

class Bip32Ed25519KeyDerivation implements Bip32ChildKeyDerivation {
  const Bip32Ed25519KeyDerivation() : this._singleton();
  const Bip32Ed25519KeyDerivation._singleton();

  static const Bip32Ed25519KeyDerivation instance =
      Bip32Ed25519KeyDerivation._singleton();

  static Uint8List _ser32LE(int index) {
    if (index < 0 || index > 0xffffffff) {
      throw InvalidBip32Ed25519IndexException();
    }

    return Uint8List(4)..buffer.asByteData().setInt32(0, index, Endian.little);
  }

  static void scalar_add(Uint8List out, int offset, Uint8List k, Uint8List k1) {
    var r = 0;

    for (var i = 0; i < 32; i++) {
      r = k[i] + k1[i] + r;
      out[i + offset] = r;
      r >>= 8;
    }
  }

  static void scalar_mul_8(Uint8List out, Uint8List k, int bytes) {
    var r = 0;
    for (var i = 0; i < bytes; i++) {
      out[i] = (k[i] << 3) + (r & 0x7);
      r = k[i] >> 5;
    }
    out[bytes] = k[bytes - 1] >> 5;
  }

  static void scalar_add_modulo_2_256(Uint8List out, int outOff, Uint8List op1,
      int op1Off, Uint8List op2, int op2Off) {
    var carry = 0;
    for (var i = 0; i < 32; i++) {
      var a = op1[i + op1Off];
      var b = op2[i + op2Off];
      var r = a + b + carry;
      out[i + outOff] = r & 0xff;
      carry = (r >= 0x100) ? 1 : 0;
    }
  }

  static Uint8List _derive(Bip32Key parentKey, List<int> prefixes, int index) {
    final out = Uint8List(64);
    final hardened = index >= Bip32KeyTree.hardenedIndex;

    final suffix = _ser32LE(index); // Throws Exception on failure

    // If hardened the key must be a private key
    if (hardened && (parentKey is Bip32PublicKey)) {
      throw InvalidBip23Ed25519DerivationKeyError();
    }

    final prefix = hardened ? prefixes[0] : prefixes[1];

    // Bip32Key has publicKey property which always points to the valid public key.
    final key = hardened ? parentKey : parentKey.publicKey;

    _deriveMessage(out, (key as Bip32Key), prefix, suffix);

    return out;
  }

  static Uint8List _deriveMessage(
      Uint8List out, Bip32Key parentKey, int prefix, Uint8List suffix) {
    final messageBytes = [prefix, ...parentKey.rawKey, ...suffix].toUint8List();

    TweetNaClExt.crypto_auth_hmacsha512(
        out, messageBytes, parentKey.chainCode.asTypedList);
    return out;
  }

  // Z is a 64-byte long sequence.
  // Zl the left 32 bytes, is used for generating the private key part of the
  // extended key, while Zr the righ 32 bytes is used for signatures.
  static Uint8List _deriveZ(Bip32Key parentKey, int index) =>
      _derive(parentKey, [0x00, 0x02], index);

  // ChainCode is the right 32-byte sequence
  static Uint8List _deriveC(Bip32Key parentKey, int index) =>
      _derive(parentKey, [0x01, 0x03], index).sublist(32);

  /// Public parent key to public child key
  ///
  /// I computes a child extended private key from the parent extended private key.
  @override
  Bip32PrivateKey ckdPriv(Bip32PrivateKey parentKey, int index) =>
      _ckd(parentKey, index) as Bip32PrivateKey;

  /// Public parent key to public child key
  ///
  /// It computes a child extended public key from the parent extended public key.
  /// It is only defined for non-hardened child keys.
  @override
  Bip32PublicKey ckdPub(Bip32PublicKey parentKey, int index) =>
      _ckd(parentKey, index) as Bip32PublicKey;

  /// Private parent key to public Child key
  ///
  /// It computes the extended public key corresponding to an extended private
  /// key a.k.a the `neutered` version, as it removes the ability to sign transactions.
  ///
  @override
  Bip32PublicKey neuterPriv(Bip32PrivateKey k) =>
      Bip32VerifyKey(k.publicKey.asTypedList);

  static Bip32Key _ckd(Bip32Key parentKey, int index) {
    final ci = _deriveC(parentKey, index);
    final _Z = _deriveZ(parentKey, index);

    final _8Zl = Uint8List(32);
    scalar_mul_8(_8Zl, _Z, 28);

    if (parentKey is Bip32PublicKey) {
      final _8ZlB = Uint8List(32);
      final K = Uint8List(32);

      // Ai = 8 * _Zl * B + Ap
      //_8Zl = 8 * _Zl
      scalar_mul_8(_8Zl, _Z, 28);
      // _8ZlB = 8 * _Zl * B
      TweetNaClExt.crypto_scalar_base(_8ZlB, _8Zl);
      // _Ai = _8ZlB + Ap
      TweetNaClExt.crypto_point_add(K, parentKey.asTypedList, _8ZlB);

      return Bip32VerifyKey.fromKeyBytes(K, ci);
    } else {
      /// Tree depth check for exceeding the limits.
      final depth = (parentKey as Bip32SigningKey).depth + 1;

      /// We simply throw Error as it simply an adversary action.
      if (depth > Bip32Ed25519.maxDepth) {
        throw MaxDepthExceededBip23Ed25519DerivationKeyError();
      }
      final k = Uint8List(64);

      // k = kl + kr
      // kl for public key generation
      // kR for signatures
      // kl = _8Zl + kpL
      scalar_add(k, 0, _8Zl, parentKey.asTypedList);
      // kr = _Zr + kpr mod 2^256
      scalar_add_modulo_2_256(k, 32, _Z, 32, parentKey.asTypedList, 32);

      final result = Bip32SigningKey.fromKeyBytes(k, ci, depth: depth);
      return result;
    }
  }
}

class Bip32VerifyKey extends VerifyKey with Suffix, Bip32PublicKey {
  Bip32VerifyKey(Uint8List publicBytes)
      : super(publicBytes, keyLength: keyLength) {
    _chainCode = ChainCode(suffix);
  }

  Bip32VerifyKey.decode(String data, {Encoder coder = decoder})
      : super.decode(data, coder: coder, keyLength: keyLength) {
    _chainCode = ChainCode(suffix);
  }

  Bip32VerifyKey.fromKeyBytes(Uint8List pubBytes, Uint8List chainCodeBytes,
      {int depth = 0})
      : this([...pubBytes, ...chainCodeBytes].toUint8List());

  @override
  int get prefixLength => keyLength - ChainCode.chainCodeLength;

  static const keyLength = 64;

  @override
  ByteList get rawKey => prefix;

  late final ChainCode _chainCode;

  @override
  ChainCode get chainCode => _chainCode;

  @override
  Bip32VerifyKey get neutered => this;

  @override
  Bip32VerifyKey derive(index) {
    return Bip32Ed25519KeyDerivation.instance.ckdPub(this, index)
        as Bip32VerifyKey;
  }

  static const decoder = Bech32Encoder(hrp: 'root_xpk');

  @override
  Encoder get encoder => decoder;
}

class Bip32SigningKey extends ExtendedSigningKey with Bip32PrivateKey {
  /// Throws Error as it is very dangerous to have non prune-to-buffered bytes.
  Bip32SigningKey(Uint8List secretBytes, {int depth = 0})
      : this.normalizeBytes(validateKeyBits(secretBytes), depth: depth);

  Bip32SigningKey.decode(String key, {Encoder coder = decoder})
      : this(coder.decode(key));

  Bip32SigningKey.generate()
      : this.normalizeBytes(TweetNaCl.randombytes(keyLength));

  Bip32SigningKey.normalizeBytes(Uint8List secretBytes, {int depth = 0})
      : this.fromValidBytes(clampKey(secretBytes), depth: depth);

  Bip32SigningKey.fromValidBytes(Uint8List secret, {this.depth = 0})
      : _verifyKey = _toPublic(validateKeyBits(secret)),
        super.fromValidBytes(validateKeyBits(secret), keyLength: keyLength) {
    _chainCode = ChainCode(suffix);
  }

  Bip32SigningKey.fromKeyBytes(Uint8List secret, Uint8List chainCode,
      {int depth = 0})
      : this.fromValidBytes([...secret, ...chainCode].toUint8List(),
            depth: depth);

  static Bip32VerifyKey _toPublic(Uint8List secret) {
    var left = List.filled(TweetNaCl.publicKeyLength, 0);
    var pk = (left +
            secret.toUint8List().sublist(keyLength - ChainCode.chainCodeLength))
        .toUint8List();

    TweetNaClExt.crypto_scalar_base(pk, secret.toUint8List());
    return Bip32VerifyKey(pk);
  }

  static Uint8List validateKeyBits(Uint8List bytes) {
    bytes = ExtendedSigningKey.validateKeyBits(bytes);

    if ((bytes[31] & 32) != 0) {
      throw InvalidSigningKeyError();
    }
    return bytes;
  }

  static Uint8List clampKey(Uint8List bytes) {
    bytes = ExtendedSigningKey.clampKey(bytes, keyLength);
    // clear the 3rd bit
    bytes[31] &= 0xDF;
    return bytes;
  }

  @override
  int get prefixLength => keyLength - ChainCode.chainCodeLength;

  static const keyLength = 96;

  @override
  final int depth;

  @override
  ByteList get rawKey => prefix;

  @override
  ChainCode get chainCode => _chainCode;
  late final ChainCode _chainCode;
  final Bip32VerifyKey _verifyKey;

  @override
  Bip32VerifyKey get verifyKey => _verifyKey;

  @override
  Bip32VerifyKey get publicKey => verifyKey;

  @override
  Bip32VerifyKey get neutered =>
      Bip32Ed25519KeyDerivation.instance.neuterPriv(this) as Bip32VerifyKey;

  @override
  Bip32SigningKey derive(index) {
    return Bip32Ed25519KeyDerivation.instance.ckdPriv(this, index)
        as Bip32SigningKey;
  }

  static const decoder = Bech32Encoder(hrp: 'root_xsk');

  @override
  Encoder get encoder => decoder;
}
