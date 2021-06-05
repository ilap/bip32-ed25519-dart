import 'package:bip32_ed25519/api.dart';
import 'package:bip32_ed25519/cardano.dart';
import 'package:pinenacl/digests.dart';

/// Byron type is not supported.
enum AddressType { Base, Pointer, Enterprise, Reward }

/// Credential types.
enum CredentialType { Key, Script }

/// We do not consider Byron's protocol magic
enum NetworkTag { testnet, mainnet }

abstract class CredentialHash extends ByteList {
  CredentialHash(List<int> bytes) : super(bytes, defaultHashLength);

  CredentialType get kind;
  static const defaultHashLength = 28;
}

class KeyHash extends CredentialHash {
  KeyHash(List<int> bytes) : super(bytes);

  @override
  CredentialType get kind => CredentialType.Key;
}

class ScriptHash extends CredentialHash {
  ScriptHash(List<int> bytes) : super(bytes);

  @override
  CredentialType get kind => CredentialType.Script;
}

abstract class ShelleyAddress extends ByteList {
  static const defaultPrefix = 'addr';
  static const defaultTail = '_test';

  final NetworkTag networkTag;

  ShelleyAddress(this.networkTag, List<int> bytes) : super(bytes);

  static String _computeHrp(NetworkTag id, String prefix) {
    return id == NetworkTag.testnet
        ? prefix + ShelleyAddress.defaultTail
        : prefix;
  }

  String toBech32({String? prefix}) {
    prefix ??= _computeHrp(networkTag, defaultPrefix);

    return this.encode(Bech32Coder(hrp: prefix));
  }

  static ShelleyAddress fromBech32(String address) {
    final decoded = bech32.decode(address, 256);
    final hrp = decoded.hrp;

    final bytes = Bech32Coder(hrp: hrp).decode(address);
    return fromBytes(bytes);
  }

  static ShelleyAddress fromBytes(List<int> bytes) {
    final header = bytes[0];
    final networkTag = NetworkTag.values[header & 0x0f];

    final addrType = (header & 0xf0) >> 4;
    switch (addrType) {
      // Base Address
      case 0:
      case 1:
      case 2:
      case 3:
        if (bytes.length != 1 + CredentialHash.defaultHashLength * 2) {
          // FIXME: Create proper error classes
          throw Error();
        }
        return BaseAddress(
            networkTag,
            _getCredentialType(header, bytes.getRange(1, 29).toList(), bit: 4),
            _getCredentialType(
                header, bytes.skip(1 + CredentialHash.defaultHashLength).toList(),
                bit: 5));

      // Pointer Address
      case 4:
      case 5:
        var byteIndex = 1 + CredentialHash.defaultHashLength;
        final paymentCred = _getCredentialType(
            header, bytes.getRange(1, byteIndex).toList(),
            bit: 4);

        final slotTuple = ChainPointer.decode(bytes.skip(byteIndex).toList());

        byteIndex += slotTuple.readedBytes;
        final txTuple = ChainPointer.decode(bytes.skip(byteIndex).toList());

        byteIndex += txTuple.readedBytes;
        final certTuple = ChainPointer.decode(bytes.skip(byteIndex).toList());

        if (byteIndex + certTuple.readedBytes < bytes.length) {
          throw Exception(
              'Fixme - throw error in address encoding/decoding instead!');
        }
        return PointerAddress(
            networkTag,
            paymentCred,
            ChainPointer(
                slot: slotTuple.number,
                txIndex: txTuple.number,
                certIndex: certTuple.number));

      // Enterprise Address
      case 6:
      case 7:
        if (bytes.length != 1 + CredentialHash.defaultHashLength) {
          // FIXME: Create proper error classes
          throw Error();
        }
        return EnterpriseAddress(networkTag,
            _getCredentialType(header, bytes.skip(1).toList(), bit: 4));

      // Stake (chmeric) Address
      case 14:
      case 15:
        if (bytes.length != 1 + CredentialHash.defaultHashLength) {
          // FIXME: Create proper error classes
          throw Error();
        }
        return RewardAddress(networkTag,
            _getCredentialType(header, bytes.skip(1).toList(), bit: 4));

      default:
        throw Exception('Unsupported Cardano Address, type: ${header}');
    }
  }

  /// If the nth bit is 0 that means it's a key hash, otherwise it's script hash.
  ///
  static CredentialHash _getCredentialType(int header, List<int> bytes,
      {required int bit}) {
    if (header & (1 << bit) == 0) {
      return KeyHash(bytes);
    } else {
      return ScriptHash(bytes);
    }
  }

  static List<int> _computeBytes(
      NetworkTag networkTag, AddressType addressType, CredentialHash paymentBytes,
      {CredentialHash? stakeBytes}) {
    switch (addressType) {
      case AddressType.Base:
        if (stakeBytes == null) {
          throw Exception('Base address requires Stake credential');
        }
        final header = (networkTag.index & 0x0f) |
            (paymentBytes.kind.index << 4) |
            (stakeBytes.kind.index << 5);
        return [header] + paymentBytes + stakeBytes;
      case AddressType.Enterprise:
        final header =
            0x60 | (networkTag.index & 0x0f) | (paymentBytes.kind.index << 4);
        return [header] + paymentBytes;
      case AddressType.Pointer:
        final header =
            0x40 | (networkTag.index & 0x0f) | (paymentBytes.kind.index << 4);
        return [header] + paymentBytes;
      case AddressType.Reward:
        final header =
            0xe0 | (networkTag.index & 0x0f) | (paymentBytes.kind.index << 4);
        return [header] + paymentBytes;
      default:
        throw Exception('Unsupported address header');
    }
  }
}

class BaseAddress extends ShelleyAddress {
  BaseAddress(
    NetworkTag networkTag,
    CredentialHash paymentBytes,
    CredentialHash stakeBytes,
  ) : super(
            networkTag,
            ShelleyAddress._computeBytes(
                networkTag, AddressType.Base, paymentBytes,
                stakeBytes: stakeBytes));
}

class EnterpriseAddress extends ShelleyAddress {
  EnterpriseAddress(NetworkTag networkTag, CredentialHash hashBytes)
      : super(
            networkTag,
            ShelleyAddress._computeBytes(
                networkTag, AddressType.Enterprise, hashBytes));
}

class PointerAddress extends ShelleyAddress {
  PointerAddress(
      NetworkTag networkTag, CredentialHash hashBytes, ChainPointer chainPointer)
      : super(
            networkTag,
            ShelleyAddress._computeBytes(
                    networkTag, AddressType.Pointer, hashBytes) +
                _encodePointer(chainPointer));

  static List<int> _encodePointer(ChainPointer pointer) {
    var result = ChainPointer.encode(pointer.slot);
    result += ChainPointer.encode(pointer.txIndex);
    result += ChainPointer.encode(pointer.certIndex);

    return result;
  }
}

class PointerTuple {
  PointerTuple(this.number, this.readedBytes);
  final int number;
  final int readedBytes;
}

/// From Ledger Spec
///
/// The variable-length encoding used in pointers addresses is the base-128 representation of the
/// number, with the the most significant bit of each byte indicating continuation. If the significant
/// bit is 0, then another bytes follows.
///
class ChainPointer {
  ChainPointer(
      {required this.slot, required this.txIndex, required this.certIndex});
  final int slot;
  final int txIndex;
  final int certIndex;

  ///
  /// For 32-bit architecture it's a 2^32-1 big number
  /// which last for 68 years for slots. We also can assume that 32-bit
  /// arch won't really exist in that time.
  /// TODO: Make it ready for slots bigger than 2^32-1
  ///
  static List<int> encode(int number) {
    final result = List<int>.filled(1, number & 0x7f, growable: true);

    number >>= 7;
    while (number > 0) {
      result.insert(0, (number & 0x7f) | 0x80);
      number >>= 7;
    }
    return result;
  }

  static PointerTuple decode(List<int> bytes) {
    var result = 0;
    var bytesReaded = 0;

    for (final byte in bytes) {
      result = (result << 7) | (byte & 0x7f);
      bytesReaded += 1;

      if ((byte & 0x80) == 0) {
        return PointerTuple(result, bytesReaded);
      }
    }

    throw Exception('Wrong Base128 conversion');
  }
}

class RewardAddress extends ShelleyAddress {
  RewardAddress(NetworkTag networkTag, CredentialHash hashBytes)
      : super(
            networkTag,
            ShelleyAddress._computeBytes(
                networkTag, AddressType.Reward, hashBytes));
}

void main() {
  const seed =
      '475083b81730de275969b1f18db34b7fb4ef79c66aa8efdd7742f1bcfe204097';
  const addressPath = "m/1852'/1815'/0'/0/0";
  const rewardAddressPath = "m/1852'/1815'/0'/2/0";

  final icarusKeyTree = CardanoIcarusKey.seed(seed);

  final addressKey = icarusKeyTree.pathToKey(addressPath);
  final rewardKey = icarusKeyTree.pathToKey(rewardAddressPath);

  final addresses = [
    'addr_test1qz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3jcu5d8ps7zex2k2xt3uqxgjqnnj83ws8lhrn648jjxtwq2ytjqp',
    'addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3jcu5d8ps7zex2k2xt3uqxgjqnnj83ws8lhrn648jjxtwqfjkjv7',
    'addr_test1vz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzerspjrlsz',
    'addr1vx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzers66hrl8',
    'addr_test1qpu5vlrf4xkxv2qpwngf6cjhtw542ayty80v8dyr49rf5ewvxwdrt70qlcpeeagscasafhffqsxy36t90ldv06wqrk2qum8x5w',
    'addr1q9u5vlrf4xkxv2qpwngf6cjhtw542ayty80v8dyr49rf5ewvxwdrt70qlcpeeagscasafhffqsxy36t90ldv06wqrk2qld6xc3',
    'addr1gyy6nhfyks7wdu3dudslys37v252w2nwhv0fw2nfawemmnyph3wczvf2dqflgt'
  ];

  for (final address in addresses) {
    final decoded = ShelleyAddress.fromBech32(address);
    assert(decoded.toBech32() == address);
  }
  // Test Base128

  final stakeCred =
      KeyHash(List<int>.generate(CredentialHash.defaultHashLength, (index) => index));
  final ptrAddress = PointerAddress(NetworkTag.testnet, stakeCred,
      ChainPointer(slot: 2354556573, txIndex: 127, certIndex: 0));

  // It must be casted to be equal.
  final addr2 = ShelleyAddress.fromBytes(ptrAddress);

  assert(ptrAddress == addr2);
  print(ptrAddress == addr2);

  final encoded = ChainPointer.encode(256275757658493284);
  final decoded = ChainPointer.decode(encoded).number;
  print(decoded);

  final address = ShelleyAddress.fromBech32(
      'addr1gyy6nhfyks7wdu3dudslys37v252w2nwhv0fw2nfawemmnyph3wczvf2dqflgt');
  print(address.toBech32());
}
