# bip32-ed25519-dart
The Dart implementation of the BIP32-Ed25519 the deterministic key generation solution for the Ed25519 curve


# API Interfaces

TBD

# Key Types
- ED25519 (RFC 8032) Keys 
    - the private key is a 32-bytre long cryptographically secure random data.
- ED25519 Extended Keys
    - the private key is a 64-byte long data, and it can be interpreted as the SHA512 hashed and clear/set bit of an ED25519 private key.
    - they also can be interpreted as standalone keys, though brute-force is required for retrieving the ED25519 private key from an extended key.
- BIP32-ED25519 Keys
    - BIP32-ED25519 derivation requires that the 3rd bit of the 31th bytes of an ED25519 Extended key must be cleared.
    - This causes half of the ED25519 and ED25519 Extended keys are not backward compatible /w BIP32-ED25519 keys.


| Key ID          | Constructors                                            | Comment                                                                               | Constraints                                                                    |
|-----------------|---------------------------------------------------------|---------------------------------------------------------------------------------------|--------------------------------------------------------------------------------|
| ed25519e_sk     | ExtendedPrivateKey.generate()                           | All keys are valid, and will set the bits based on RFC8032                            | N/A                                                                            |
|                 | ExtendedPrivateKey.fromSeed(32)                         | All keys are valid, and will set the bits based on RFC8032                            | check length                                                                   |
|                 | ExtendedPrivateKey.decode('ed25519e_sk')                | Will throw excpetions if the bits are not set.                                        | check length and bits                                                          |
|                 | ExtendedPrivateKey(64)                                  | Will throw excpetions if the bits are not set.                                        | check length and bits                                                          |
|                 | public => _public()                                     | returns /w an ed25519_pk verifying key                                                | It's an expensive operation and should be created when it's first   referenced |
|                 | sign(message)                                           | returns /w a signature                                                                | N/A                                                                            |
|                 | verify(sm, sig)                                         | Simply verify by it's public key.                                                     | check sm messages and signature length                                         |
| ed25519_pk      | VerifyKey(32)                                           | All keys are valid.                                                                   | check length                                                                   |
|                 | verify(sm, sig)                                         |                                                                                       | check length(s)                                                                |
|                 | verify(sm \|\| sig)                                     |                                                                                       | check length(s)                                                                |
| ed25519bip32_sk | ExtendedBip32PrivateKey.generate()                      | All keys are valid, and will set the bits based on `Bip32-Ed25519`                    | N/A                                                                            |
|                 | ExtendedBip32Private.normalizeBytes(96)                 | All keys are valid, and will set the bits based on `Bip32-Ed25519`                    | check length                                                                   |
|                 | ExtendedBip32Private.fromVerifiedBytes(96)              | All keys should be valid but we cannot validate it.                                   | It's expensive to check the public key                                         |
|                 | ExtendedBip32PrivateKey.decode('ed25519bip32_sk')       | Will throw excpetions if the bits are not set.                                        | check length and bits                                                          |
|                 | ExtendedBip32PrivateKey(96)                             | Will throw excpetions if the bits are not set.                                        | check length and bits                                                          |
|                 | ExtendedBip32Private.fromExtended(sk64, cc32)           | Will throw excpetions if the bits are not set.                                        | check length and bits                                                          |
|                 | public => _public()                                     | Inherited from ExtendedPrivateKey                                                     | It's an expensive operation and should be created when it's first   referenced |
|                 | sign(message)                                           | Inherited from ExtendedPrivateKey                                                     | check length(s)                                                                |
|                 | verify(sm, sig)                                         | Inherited from ExtendedPrivateKey                                                     | check sm messages and signature length                                         |
|                 | verify(sm \|\| sig)                                     | Inherited from ExtendedPrivateKey                                                     | check length(s)                                                                |
|                 | derive(index)                                           | Inherited from ExtendedPrivateKey                                                     | check index                                                                    |
|                 | chainCode => ChainCode(suffix)                          | Returns /w a chain code value object                                                  | check length(s)                                                                |
|                 | getExtended => ExtendedPrivateKey.fromValidBytes(64)    | Returns and extended key as every   `Bip32-Ed25519` is a valid `Extended Ed25519` key |                                                                                |
| ed25519bip32_pk | ExtendedBip32PublicKey(64)                              | All keys are valid                                                                    | check length(s)                                                                |
|                 | ExtendedBip32PublicKey.fromKey(pk32, cc32)              | All keys are valid                                                                    | check length(s)                                                                |
|                 | verify(sm, sig)                                         | Inherited from VerifyKey                                                              | check length(s)                                                                |
|                 | verify(sm \|\| sig)                                     | Inherited from VerifyKey                                                              | check length(s)                                                                |
|                 | derive(index)                                           | Inherited from VerifyKey                                                              | check index range                                                              |
|                 | chainCode => ChainCode(suffix)                          | Returns /w a chain code value object                                                  | check length                                                                   |
|                 | getExtended => ExtendedPublicKey.fromValidBytes(prefix) | Returns and extended key as every `Bip32-Ed25519` is a valid `Extended   Ed25519` key | It's cheap operation                                                           |
### ED25519 Keys

The [ed25519](http://ed25519.cr.yp.to/) is an 
[Elliptic Curve Digital Signature Algortithm](http://en.wikipedia.org/wiki/Elliptic_Curve_DSA) using curve25519 by [Dan Bernstein](http://cr.yp.to/djb.html), 
[Niels Duif](http://www.nielsduif.nl/), 
[Tanja Lange](http://hyperelliptic.org/tanja), 
[Peter Schwabe](http://www.cryptojedi.org/users/peter/), 
and [Bo-Yin Yang](http://www.iis.sinica.edu.tw/pages/byyang/).

The key is 64-byte long and contains the the 32-byte long seed a.k.a private key that is used for 
generate the secret key and public key.

### ED25519 Extended keys

The 64-byte long extended keys contains either 
    - only the 64-byte long secret key.
    - or the 64-byte long extended private key and the 32-byte public key similar to the normal 
    ED25519 key whihc contains the 32-byte private key (seed) and the 32-byte long private key.

Though, `pinenacl-dart`'s extended interface expecting a concatenated secret and public key.
It's due to the assumption that the public key is already known (no scalar_base multiplication is needed for retrieveing the key)

The [message signing and signature verifying is compatible /w ED25519](https://raw.githubusercontent.com/RubyCrypto/ed25519/master/ed25519.png).


### BIP32-ED25519 Keys

The 96-byte long BIP32-ED25519 keys contains the ed25519e_sk and the chain code.
The message signing and signature verifying is compatible /w ED25519.

Note: 


# Restrictions

In Cardano blockchain, the keys are derived by the `BIP32-ED25519` specification.

The `BIP32-ED25519`, in addition to the `ED25519` [(RFC 8032)](https://tools.ietf.org/html/rfc8032), needs the 3rd bit cleared of the 31th byte.

Therefore, the half of the `ED25519 Extended` secret keys and therefore the half of the  `ED25519` private keys are not compatible /w `BIP32-ED25519`.

To overcome of this restriction, different wallet implementation decided to generate their master node/root key differently (as BIP32-ED25519 specification only requires that bit cleared on the master node/root key as the derived keys would have that bit cleared in the derivation functions anyway). 

Some of them (such as Yoroi), just clear that `additional` 3rd bit, while others (such as the old Daedalus) are hashing the corresponding master key until they find a compatible key, and when it's found, they set and clear the bits as specified in the `RFC 8032`.

 ## Resolution

There are different type of resolutions. The most proper way would be: generate only a `BIP32-ED25519` compatible 24-word mnemonics and therefore a 256-bit long master secret for new wallets and discard others.
Then use that 256-bit master secret as `k` specified in `BIP32-ED25519`.

Drawback of this is that half of the already existing user's mnemonics are not compatible, therefore
they need either to move to a new wallet or using some out-dated master-key generation algorithm.
