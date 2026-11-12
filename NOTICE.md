# Sources and compatibility references

- Identity search and CLI semantics: Oliver Gugger's
  [chantools vanitygen](https://github.com/lightninglabs/chantools/blob/master/cmd/chantools/vanitygen.go), MIT.
  The Rust derivation follows BIP32 and retains fixed-width private scalars.
  Invalid derivations discard the candidate rather than changing the identity path.
- Aezeed layout and compatibility vectors:
  [LND aezeed](https://github.com/lightningnetwork/lnd/tree/master/aezeed), MIT.
  LND's vector tests set scrypt N=16; production uses N=32768.
- The Rust AEZv5 Tiny/Hash implementation follows Yawning Angel's
  [AEZ implementation](https://github.com/Yawning/aez), CC0.
  This implementation intentionally handles only aezeed's fixed 23-byte Tiny case.
- `data/english.txt` is the standard English BIP39 word list, also used by aezeed,
  extracted from chantools' MIT-licensed copy of go-bip39's word list.
- SHA-512 constants and algorithms: FIPS 180-4. Curve: secp256k1 / SEC 2.

Dependencies have their own license terms, available in their distributed source.
Original reference license notices are retained in `licenses/`.
