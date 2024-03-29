import 'package:bip32_ed25519/api.dart';

void main() {
  const hex = Base16Encoder.instance;
  print('\n### BIP32 Digital Signatures ###\n');

  /// Signer’s perspective (SigningKey)
  ///
  // Generate a new random signing key
  final signingKey = Bip32SigningKey.generate();

  final message = 'People see the things they want to see...';
  final forgedMessage = 'people see the things they want to see...';
  // Sign a message with the signing key
  final signed = signingKey.sign(message.codeUnits);

  //  Obtain the verify key for a given signing key
  final verifyKey = signingKey.verifyKey;

  // Serialize the verify key to send it to a third party
  final verifyKeyHex = verifyKey.encode(hex);

  ///
  /// Verifier’s perspective (VerifyKey)
  ///
  final verifyKey2 = Bip32VerifyKey.decode(verifyKeyHex, coder: hex);
  assert(verifyKey == verifyKey2);
  print('The "$message" is successfully verified');

  // Check the validity of a message's signature
  // The message and the signature can either be passed separately or
  // concatenated together.  These are equivalent:
  verifyKey.verifySignedMessage(signedMessage: signed);
  verifyKey.verify(
      signature: signed.signature, message: signed.message.asTypedList);

  try {
    // Forged message.
    verifyKey.verify(
        signature: signed.signature,
        message: Uint8List.fromList(forgedMessage.codeUnits));
  } on Exception catch (e) {
    print('Exception\'s successfully cought:\n$e');
  }
}
