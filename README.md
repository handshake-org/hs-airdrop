# Airdrop

Redemption tool for the Handshake network's decentralized airdrop to open
source developers.

## How it works

The top ~250,000 users on github have had their SSH keys and PGP added to a
[merkle tree][tree]. Out of those ~250,000 users, ~175,000 of them had valid
SSH and PGP keys at the time of tree creation.

If you had 15 or more followers on github during the week of 2018-08-27, your
github SSH & PGP keys are included in the merkle tree.

Likewise, roughly 30,000 keys from the PGP WOT Strongset have also been
included in the tree.

This merkle tree is computed and its root is added to consensus rules of the
Handshake blockchain, allowing the owner of a key to publish a signed merkle
proof on-chain in order to redeem their airdrop.

With the key list as it currently stands, every open source developer will
receive __4,246.994314__ HNS coins from the airdrop.

---

There are a few gotchas: we do not allow standard PGP signatures on the
consensus layer. This is done for simplicity and safety. This means that a
regular call to `$ gpg --sign` will not work for handshake airdrop proofs. As
far as SSH keys go, people typically do not sign arbitrary messages with them.

Because of this, we require a special tool to do both the signing and merkle
proof creation.

## Privacy

An airdrop to Github and PGP users presents an obvious privacy concern: Github
and PGP keys are generally tied to a person's real identity. While impractical,
a determined analyst could link an on-chain airdrop redemption to a
person's identity.

To solve the privacy issue in a non-interactive way, a 32 byte scalar has been
[encrypted to][nonces] your public key (you will have to grind a file full of
encrypted blobs to find it). For EC keys, this scalar is meant to be _added_ to
your existing key pair (a la HD derivation). For RSA keys, a much more
[complicated setup][goosig] is necessary. In either case, once your _new_ key
is derived using this scalar, you will be able to find its corresponding leaf
in the merkle tree published above.

Publishing a signed airdrop proof using this method _does not_ leak any
information about your actual identity.

The full list of keys will be destroyed upon mainnet launch. Plaintext nonces
are not saved at all during the generation phase. The ephemeral keys used for
the ECIES key exchanges are also not saved.

## Security

If you're uncomfortable having third party software access your PGP and SSH
keys, you are always able to generate this proof on an air-gapped machine. QR
code generation will be added to this tool for convenience (eventually).

Signed tarballs of this software will be released upon mainnet launch.

## Fallback for HSMs

Not everyone keeps their SSH and PGP keys on their laptop. In the event that
your key is not accessible by the signing tool, the signing tool can present
you with the raw data needed to be signed. Your regular key is _also_ included
in the merkle tree (concatenated with a random nonce, seeded by the encrypted
scalar to preserve privacy). Unfortunately, this will forgo the privacy
preservation mechanism described above.

## Accepted Key Algorithms

To simplify consensus implementation, we only allow the top 3 most popular key
algorithms used on github:

- __RSA__ (1024 to 4096 bit modulus, e <= 33 bits) - See the Handshake paper as
  to why 1024 bit moduli are considered acceptable.
- __Ed25519__
- __P256__ (NIST curve)

## Faucet Migration

If you submitted an address to the Handshake faucet, it will be included in the
mainnet merkle tree.

## Usage

The airdrop tree was most recently updated on
[Feb 2, 2020](https://github.com/handshake-org/hs-airdrop/commit/9ab50eeb5b3f6ceb785cc94394facc6ea630096c).
If you have ever run `hs-airdrop` before then, you will need to download the program
again from this repo AND clear the old tree data from your drive.
The old tree data will be in your home directory at `~/.hs-tree-data`.
Once removed, `hs-airdrop` will download the updated tree from
[this source](https://github.com/handshake-org/hs-tree-data).

Transactions are not allowed for the first 2,016 blocks on main net (about 2 weeks),
and will be rejected by network peers. Be sure to wait before sending your proof!

```
$ hs-airdrop
hs-airdrop v0.0.3

This tool will create the proof necessary to
collect your faucet reward, airdrop reward, or
sponsor reward on the Handshake blockchain.

Usage: $ hs-airdrop [key-file] [id] [addr] [fee] --bare
       $ hs-airdrop [key-file] [addr] [fee] --bare
       $ hs-airdrop [addr]
       $ hs-airdrop [addr] [value/shares]
       $ hs-airdrop [addr] [value] --sponsor

  [key-file] can be:
    - An SSH private key file.
    - An exported PGP armor keyring (.asc).
    - An exported PGP raw keyring (.pgp/.gpg).

  [id] is only necessary for PGP keys.

  [addr] must be a Handshake bech32 address.
  [value] may be the coin value awarded to you (in HNS).
  [shares] may be the num. of shares awarded by the faucet.
  [fee] must be a coin value (in HNS).

  The --sponsor flag is necessary for project sponsors.

  The --bare flag will use your existing public key.
  This is not recommended as it makes you identifiable
  on-chain.

  This tool will provide a JSON representation of
  your airdrop proof as well as a base64 string.

  The base64 string must be passed to:
    $ hsd-rpc sendrawairdrop "base64-string"

Examples:
  $ hs-airdrop ~/.gnupg/secring.gpg 0x12345678 ts1q5z7yym8xrh4quqg3kw498ngy7hnd4sruqyxnxd 0.5
  $ hs-airdrop ~/.ssh/id_rsa ts1q5z7yym8xrh4quqg3kw498ngy7hnd4sruqyxnxd 0.5
  $ hs-airdrop ~/.ssh/id_rsa ts1q5z7yym8xrh4quqg3kw498ngy7hnd4sruqyxnxd 0.5 --bare
  $ hs-airdrop ts1q5z7yym8xrh4quqg3kw498ngy7hnd4sruqyxnxd
  $ hs-airdrop ts1q5z7yym8xrh4quqg3kw498ngy7hnd4sruqyxnxd 5000
  $ hs-airdrop ts1q5z7yym8xrh4quqg3kw498ngy7hnd4sruqyxnxd 2 # shares
  $ hs-airdrop ts1q5z7yym8xrh4quqg3kw498ngy7hnd4sruqyxnxd 1000000 --sponsor
```

If you are not in the faucet tree, you need to use this tool to generate a proof with your GitHub key. All you need to pass is your key file and a Handshake address:

```
  $ hs-airdrop [key-file] [addr]
```

## License

MIT License.

- Copyright (c) 2018, Christopher Jeffrey (https://github.com/chjj)
- Copyright (c) 2018, Handshake Contributors (https://github.com/handshake-org)

See LICENSE for more info.

[tree]: https://github.com/handshake-org/hs-tree-data
[nonces]: https://github.com/handshake-org/hs-tree-data/tree/master/nonces
[goosig]: https://github.com/handshake-org/goosig
