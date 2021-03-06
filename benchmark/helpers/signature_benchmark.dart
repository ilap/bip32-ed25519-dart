import 'package:bip32_ed25519/api.dart';

import 'rate_benchmark.dart';

class SignatureBenchmark extends RateBenchmark {
  SignatureBenchmark(String signerName, bool forSigning,
      [int dataLength = 1024 * 1024])
      : _forSigning = forSigning,
        _data = Uint8List(dataLength),
        super('Signatures | $signerName - ${forSigning ? 'sign  ' : 'verify'}');

  final Uint8List _data;
  final bool _forSigning;
  late final SigningKey _signer;
  SignedMessage? _signature;

  @override
  void setup() {
    final signingKey = Bip32SigningKey.generate();

    _signer = signingKey;
    _signature = _signer.sign(_data);
  }

  @override
  void run() {
    if (_forSigning) {
      _signer.sign(_data);
    } else if (_signature != null) {
      _signer.verifyKey.verifySignedMessage(signedMessage: _signature!);
    }
    addSample(_data.length);
  }
}
