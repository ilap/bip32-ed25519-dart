// ignore_for_file: constant_identifier_names

import 'package:bip32_ed25519/cardano.dart';

///
/// Address format
///
enum AddressType { Base, Pointer, Enterprise, Reward }

enum CredentialType { Key, Script }

/// We do not consider Byron's protocol magic
enum NetworkId { testnet, mainnet }

abstract class CredentialHash extends ByteList {
  CredentialHash(List<int> bytes)
      : super.withConstraint(bytes, constraintLength: hashLength);
  int get kind;
  static const hashLength = 28;
}

class KeyHash extends CredentialHash {
  KeyHash(List<int> bytes) : super(bytes);

  @override
  int get kind => CredentialType.Key.index;
}

class ScriptHash extends CredentialHash {
  ScriptHash(List<int> bytes) : super(bytes);

  @override
  int get kind => CredentialType.Key.index;
}

abstract class ShelleyAddress extends ByteList {
  ShelleyAddress(this.networkId, List<int> bytes) : super(bytes);

  static const defaultPrefix = 'addr';
  static const defaultTail = '_test';

  final NetworkId networkId;

  static String _computeHrp(NetworkId id, String prefix) {
    return id == NetworkId.testnet
        ? prefix + ShelleyAddress.defaultTail
        : prefix;
  }

  String toBech32({String? prefix}) {
    prefix ??= _computeHrp(networkId, defaultPrefix);

    return encode(Bech32Encoder(hrp: prefix));
  }

  static ShelleyAddress fromBech32(String address) {
    final decodedBytes = Bech32Encoder.decodeNoHrpCheck(address, 256);

    return fromBytes(decodedBytes);
  }

  static ShelleyAddress fromBytes(List<int> bytes) {
    final header = bytes[0];
    final networkId = NetworkId.values[header & 0x0f];

    final addrType = (header & 0xf0) >> 4;
    switch (addrType) {
      // Base Address
      case 0:
      case 1:
      case 2:
      case 3:
        if (bytes.length != 1 + CredentialHash.hashLength * 2) {
          // FIXME: Create proper error classes
          throw Error();
        }
        return BaseAddress(
            networkId,
            _getCredentialType(header, bytes.getRange(1, 29).toList(), bit: 4),
            _getCredentialType(
                header, bytes.skip(1 + CredentialHash.hashLength).toList(),
                bit: 5));

      // Pointer Address
      case 4:
      case 5:
        var byteIndex = 1 + CredentialHash.hashLength;
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
            networkId,
            paymentCred,
            ChainPointer(
                slot: slotTuple.number,
                txIndex: txTuple.number,
                certIndex: certTuple.number));

      // Enterprise Address
      case 6:
      case 7:
        if (bytes.length != 1 + CredentialHash.hashLength) {
          // FIXME: Create proper error classes
          throw Error();
        }
        return EnterpriseAddress(networkId,
            _getCredentialType(header, bytes.skip(1).toList(), bit: 4));

      // Stake (chimeric) Address
      case 14:
      case 15:
        if (bytes.length != 1 + CredentialHash.hashLength) {
          // FIXME: Create proper error classes
          throw Error();
        }
        return RewardAddress(networkId,
            _getCredentialType(header, bytes.skip(1).toList(), bit: 4));

      default:
        throw Exception('Unsupported Cardano Address, type: $header');
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
      NetworkId networkId, AddressType addressType, CredentialHash paymentBytes,
      {CredentialHash? stakeBytes}) {
    switch (addressType) {
      case AddressType.Base:
        if (stakeBytes == null) {
          throw Exception('Base address requires Stake credential');
        }
        final header = (networkId.index & 0x0f) |
            (paymentBytes.kind << 4) |
            (stakeBytes.kind << 5);
        return [header] + paymentBytes + stakeBytes;
      case AddressType.Enterprise:
        final header =
            0x60 | (networkId.index & 0x0f) | (paymentBytes.kind << 4);
        return [header] + paymentBytes;
      case AddressType.Pointer:
        final header =
            0x40 | (networkId.index & 0x0f) | (paymentBytes.kind << 4);
        return [header] + paymentBytes;
      case AddressType.Reward:
        final header =
            0xe0 | (networkId.index & 0x0f) | (paymentBytes.kind << 4);
        return [header] + paymentBytes;
      default:
        throw Exception('Unsupported address header');
    }
  }
}

class BaseAddress extends ShelleyAddress {
  BaseAddress(
    NetworkId networkId,
    CredentialHash paymentBytes,
    CredentialHash stakeBytes,
  ) : super(
            networkId,
            ShelleyAddress._computeBytes(
                networkId, AddressType.Base, paymentBytes,
                stakeBytes: stakeBytes));
}

class EnterpriseAddress extends ShelleyAddress {
  EnterpriseAddress(NetworkId networkId, CredentialHash hashBytes)
      : super(
            networkId,
            ShelleyAddress._computeBytes(
                networkId, AddressType.Enterprise, hashBytes));
}

class PointerAddress extends ShelleyAddress {
  PointerAddress(
      NetworkId networkId, CredentialHash hashBytes, ChainPointer chainPointer)
      : super(
            networkId,
            ShelleyAddress._computeBytes(
                    networkId, AddressType.Pointer, hashBytes) +
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
  RewardAddress(NetworkId networkId, CredentialHash hashBytes)
      : super(
            networkId,
            ShelleyAddress._computeBytes(
                networkId, AddressType.Reward, hashBytes));
}

void main() {
  //const seed =
  //    '475083b81730de275969b1f18db34b7fb4ef79c66aa8efdd7742f1bcfe204097';
  //const addressPath = "m/1852'/1815'/0'/0/0";
  //const rewardAddressPath = "m/1852'/1815'/0'/2/0";

  //final icarusKeyTree = CardanoIcarusKey.seed(seed);

  //final addressKey = icarusKeyTree.pathToKey(addressPath);
  //final rewardKey = icarusKeyTree.pathToKey(rewardAddressPath);

  var address = ShelleyAddress.fromBech32(
      'addr_test1qz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3jcu5d8ps7zex2k2xt3uqxgjqnnj83ws8lhrn648jjxtwq2ytjqp');
  print(address.toBech32());

  address = ShelleyAddress.fromBech32(
      'addr1qx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzer3jcu5d8ps7zex2k2xt3uqxgjqnnj83ws8lhrn648jjxtwqfjkjv7');
  print(address.toBech32());

  address = ShelleyAddress.fromBech32(
      'addr_test1vz2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzerspjrlsz');
  print(address.toBech32());

  address = ShelleyAddress.fromBech32(
      'addr1vx2fxv2umyhttkxyxp8x0dlpdt3k6cwng5pxj3jhsydzers66hrl8');
  print(address.toBech32());

  address = ShelleyAddress.fromBech32(
      'addr_test1qpu5vlrf4xkxv2qpwngf6cjhtw542ayty80v8dyr49rf5ewvxwdrt70qlcpeeagscasafhffqsxy36t90ldv06wqrk2qum8x5w');
  print(address.toBech32());

  address = ShelleyAddress.fromBech32(
      'addr1q9u5vlrf4xkxv2qpwngf6cjhtw542ayty80v8dyr49rf5ewvxwdrt70qlcpeeagscasafhffqsxy36t90ldv06wqrk2qld6xc3');
  print(address.toBech32());

  // Test Base128

  final stakeCred =
      KeyHash(List<int>.generate(CredentialHash.hashLength, (index) => index));
  final ptrAddress = PointerAddress(NetworkId.testnet, stakeCred,
      ChainPointer(slot: 2354556573, txIndex: 127, certIndex: 0));

  // It must be casted to be equal.
  final addr2 = ShelleyAddress.fromBytes(ptrAddress);

  assert(ptrAddress == addr2);
  print(ptrAddress == addr2);

  final encoded = ChainPointer.encode(256275757658493284);
  final decoded = ChainPointer.decode(encoded).number;
  print(decoded);

  address = ShelleyAddress.fromBech32(
      'addr1gyy6nhfyks7wdu3dudslys37v252w2nwhv0fw2nfawemmnyph3wczvf2dqflgt');
  print(address.toBech32());
}
