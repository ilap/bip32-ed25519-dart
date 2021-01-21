import 'dart:typed_data';

import 'package:pinenacl/ed25519.dart';
import 'package:pinenacl/digests.dart';
import 'package:pinenacl/tweetnacl.dart';
import 'package:bip32_ed25519/src/bip32_ed25519/ed25519_extended.dart';
import 'package:bip32_ed25519/api.dart';

// Errors
class InvalidBip23Ed25519DerivationKeyError extends Error {}

// Exceptions
class InvalidBip32Ed25519IndexException implements Exception {}

class InvalidBip32Ed25519MasterSecretException implements Exception {}

///
/// This is the dart implementation of the `BIP32-Ed25519 Hierarchical
/// Deterministic Keys over a Non-linear Keyspace` key derivation
/// algorythm.
///
class Bip32Ed25519 extends Bip32Ed25519KeyDerivation with Bip32KeyTree {
  Bip32Ed25519(Uint8List masterSeed) {
    this.root = master(masterSeed);
  }
  Bip32Ed25519.seed(String seed) {
    this.root = master(HexCoder.instance.decode(seed));
  }

  Bip32Ed25519.import(String key) {
    this.root = doImport(key);
  }

  /// The default implementation of the origianl BIP32-ED25519's master key
  /// generation.
  Bip32Key master(Uint8List masterSecret) {
    final secretBytes = Hash.sha512(masterSecret);

    if ((secretBytes[31] &= 0x20) != 0)
      throw InvalidBip32Ed25519MasterSecretException();

    final rootChainCode = Hash.sha256([0x01, ...masterSecret].toUint8List());

    final rootKey = Bip32SigningKey.normalizeBytes(
        [...secretBytes, ...rootChainCode].toUint8List());

    PineNaClUtils.listZero(masterSecret);
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

class Bip32Ed25519KeyDerivation implements Bip32ChildKeyDerivaton {
  const Bip32Ed25519KeyDerivation() : this._singleton();
  const Bip32Ed25519KeyDerivation._singleton();

  static const Bip32Ed25519KeyDerivation instance =
      Bip32Ed25519KeyDerivation._singleton();

  static Uint8List _ser32LE(int index) {
    if (index < 0 || index > 0xffffffff)
      throw InvalidBip32Ed25519IndexException();

    return Uint8List(4)..buffer.asByteData().setInt32(0, index, Endian.little);
  }

  static void scalar_add(Uint8List out, int offset, Uint8List k, Uint8List k1) {
    int r = 0;

    for (var i = 0; i < 32; i++) {
      r = k[i] + k1[i] + r;
      out[i + offset] = r;
      r >>= 8;
    }
  }

  static void scalar_mul_8(Uint8List out, Uint8List k, int bytes) {
    int r = 0;
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
      int a = op1[i + op1Off];
      int b = op2[i + op2Off];
      int r = a + b + carry;
      out[i + outOff] = r & 0xff;
      carry = (r >= 0x100) ? 1 : 0;
    }
  }

  static Uint8List _derive(Bip32Key parentKey, List<int> prefixes, int index) {
    final out = Uint8List(64);
    final hardened = index >= Bip32KeyTree.hardenedIndex;

    final suffix = _ser32LE(index); // Throws Exception on failure

    // If hardened the key must be a private key
    if (hardened && (parentKey is Bip32PublicKey))
      throw InvalidBip23Ed25519DerivationKeyError();

    final prefix = hardened ? prefixes[0] : prefixes[1];

    // Bip32Key has publicKey property which always points to the valid public key.
    final key = hardened ? parentKey : parentKey.publicKey;

    _deriveMessage(out, (key as Bip32Key), prefix, suffix);

    return out;
  }

  static Uint8List _deriveMessage(
      Uint8List out, Bip32Key parentKey, int prefix, Uint8List suffix) {
    final messageBytes =
        [prefix, ...parentKey.keyBytes, ...suffix].toUint8List();

    TweetNaClExt.crypto_auth_hmacsha512(out, messageBytes, parentKey.chainCode);
    return out;
  }

  // Z is a 64-byte long sequence.
  // Zl the left 32 bytes, is used for generating the private key part of the
  // extended key, while Zr the righ 32 bytes is used for signatures.
  Uint8List _deriveZ(Bip32Key parentKey, int index) =>
      _derive(parentKey, [0x00, 0x02], index);

  // ChainCode is the right 32-byte sequence
  Uint8List _deriveC(Bip32Key parentKey, int index) =>
      _derive(parentKey, [0x01, 0x03], index).sublist(32);

  /// Public parent key to public child key
  ///
  /// I computes a child extended private key from the parent extended private key.
  Bip32PrivateKey ckdPriv(Bip32PrivateKey parentKey, int index) =>
      _ckd(parentKey, index) as Bip32PrivateKey;

  /// Public parent key to public child key
  ///
  /// It computes a child extended public key from the parent extended public key.
  /// It is only defined for non-hardened child keys.
  Bip32PublicKey ckdPub(Bip32PublicKey parentKey, int index) =>
      _ckd(parentKey, index) as Bip32PublicKey;

  /// Private parent key to public Child key
  ///
  /// It computes the extended public key corresponding to an extended private
  /// key a.k.a the `neutered` version, as it removes the ability to sign transactions.
  ///
  Bip32PublicKey neuterPriv(Bip32PrivateKey k) => Bip32VerifyKey(k.publicKey);

  Bip32Key _ckd(Bip32Key parentKey, int index) {
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
      TweetNaClExt.crypto_point_add(K, parentKey, _8ZlB);

      return Bip32VerifyKey.fromKeyBytes(K, ci);
    } else {
      final k = Uint8List(64);

      // k = kl + kr
      // kl for public key generation
      // kR for signatures
      // kl = _8Zl + kpL
      scalar_add(k, 0, _8Zl, parentKey);
      // kr = _Zr + kpr mod 2^256
      scalar_add_modulo_2_256(k, 32, _Z, 32, parentKey, 32);

      final result = Bip32SigningKey.fromKeyBytes(k, ci);
      return result;
    }
  }
}

class Bip32VerifyKey extends VerifyKey with Bip32PublicKey {
  Bip32VerifyKey(Uint8List publicBytes, {this.depth = 0})
      : super(publicBytes, keyLength) {
    _chainCode = ChainCode(suffix);
  }

  Bip32VerifyKey.decode(String data, {Encoder coder = decoder, this.depth = 0})
      : super.decode(data, coder: coder) {
    _chainCode = ChainCode(suffix);
  }

  Bip32VerifyKey.fromKeyBytes(Uint8List pubBytes, Uint8List chainCodeBytes,
      {int depth = 0})
      : this([...pubBytes, ...chainCodeBytes].toUint8List(), depth: depth);

  @override
  final int prefixLength = keyLength - ChainCode.chainCodeLength;

  static const keyLength = 64;
  final int depth;

  @override
  ByteList get rawKey => prefix;

  late final ChainCode _chainCode;

  @override
  ChainCode get chainCode => _chainCode;

  @override
  Bip32VerifyKey derive(index) {
    return this;
  }

  static const decoder = Bech32Coder(hrp: 'ed25519bip32_pk');

  @override
  Encoder get encoder => decoder;
}

class Bip32SigningKey extends ExtendedSigningKey with Bip32PrivateKey {
  /// Throws Error as it is very dangerous to have non prune-to-buffered bytes.
  Bip32SigningKey(Uint8List secretBytes)
      : this.normalizeBytes(validateKeyBits(secretBytes));

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
    var pk = (left + secret.sublist(keyLength - ChainCode.chainCodeLength))
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
  final int prefixLength = keyLength - ChainCode.chainCodeLength;

  static const keyLength = 96;

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
  Bip32SigningKey derive(index) {
    return this;
  }

  static const decoder = Bech32Coder(hrp: 'ed25519bip32_sk');

  @override
  Encoder get encoder => decoder;
}

/*
void main() {
  const csk_0 =
      'xprv1cpfh0megyfu4fxyccks4lcszhj2pdj9zdl5plls7r8q50sjfx4yav928dydh94eegljc3hk5jemg37pdh93gh6dmqrz66944m7hkq2k97svm646l363rlgd9nxcs87z7vvjm7tf5kqv07met3nelj90pnsfjclag';
  const csk_h =
      'c05377ef282279549898c5a15fe202bc9416c8a26fe81ffe1e19c147c2493549d61547691b72d73947e588ded4967688f82db9628be9bb00c5ad16b5dfaf602ac5f419bd575f8ea23fa1a599b103f85e6325bf2d34b018ff6f2b8cf3f915e19c';

  const cpk_0 =
      'xpub19vdjcq8rtj0ect0vym8rhfvh2pxjljrgv2mqxkc9xs90lzn7h39utaqeh4t4lr4z87s6txd3q0u9uce9huknfvqclahjhr8nly27r8q5ww6gs';
  const cpk_h =
      '2b1b2c00e35c9f9c2dec26ce3ba597504d2fc86862b6035b05340aff8a7ebc4bc5f419bd575f8ea23fa1a599b103f85e6325bf2d34b018ff6f2b8cf3f915e19c';

  const esk_0 =
      'xprv1prg8t88k7zqs2uufgh4ze4qx0utnj3gh8d07x6stt45v3jzfx4y5tpdl8ea3r458cntycu7aa4vfzkgqmjdmz0cx922n92pkdhafwxkumxh9cnhnrmldaahwmtvknzs4lqgazqzqx6mxysfc2zqag9jreujgjxt0';
  const esk0h =
      '08d0759cf6f08105738945ea2cd4067f173945173b5fe36a0b5d68c8c84935494585bf3e7b11d687c4d64c73dded58915900dc9bb13f062a9532a8366dfa971adcd9ae5c4ef31efedef6eedad9698a15f811d1004036b66241385081d41643cf';

  const epk_0 =
      'xpub1wygtt6rzgrj3ks864trc5zujv907j6hdxakd6pe9tuy2u7hfee3dekdwt380x8h7mmmwakkedx9pt7q36yqyqd4kvfqns5yp6sty8ncrz8due';
  const epk0h =
      '7110b5e86240e51b40faaac78a0b92615fe96aed376cdd07255f08ae7ae9ce62dcd9ae5c4ef31efedef6eedad9698a15f811d1004036b66241385081d41643cf';

  const esk_1 =
      'xprv13z96f5ef2vysz4wte0fxh0nvd4j7w337kgdraj2ldvd0f36fx4ykku3uju42rh3ztw0gerehg6srfu70vlz3u3wynquk3vtxwex0ymyjz6uxtuumzf63tku664v3ul7tjzrqfww4q44ck7kf3num6vzccc093rc0';
  const esk1h =
      '888ba4d32953090155cbcbd26bbe6c6d65e7463eb21a3ec95f6b1af4c74935496b723c972aa1de225b9e8c8f3746a034f3cf67c51e45c4983968b166764cf26c9216b865f39b127515db9ad5591e7fcb908604b9d5056b8b7ac98cf9bd3058c6';

  const epk_1 =
      'xpub18ylxj3hgg0wn4wdvx9zjfhk8lq3wwamvhchqsjgcuugq8596l77fy94cvheekyn4zhde442ereluhyyxqjua2ptt3davnr8eh5c933sjrdkge';
  const epk1h =
      '393e6946e843dd3ab9ac314524dec7f822e7776cbe2e084918e71003d0baffbc9216b865f39b127515db9ad5591e7fcb908604b9d5056b8b7ac98cf9bd3058c6';

  final xprvCoder = Bech32Coder(hrp: 'xprv');
  final xpubCoder = Bech32Coder(hrp: 'xpub');
  final _kp = Bip32SigningKey.decode(csk_0, coder: xprvCoder);
  final _Kp = Bip32VerifyKey.decode(cpk_0, coder: xpubCoder);

  final dc = Bip32Ed25519KeyDerivation.instance;

  //final masterSecret = TweetNaCl.randombytes(32);
  //final m = dc.master(masterSecret);

  //final M = dc.forP

  Bip32PrivateKey derivedPrv;
  Bip32PublicKey derivedPub;

  for (var i = 0; i < 2; i++) {
    derivedPrv = dc.ckdPriv(_kp, i);
    derivedPub = dc.ckdPub(_Kp, i);

    print(derivedPrv.encode(xprvCoder));
    print(derivedPub.encode(xpubCoder));
    assert(dc.neuterPriv(derivedPrv) == derivedPub);
  }
}
*/
