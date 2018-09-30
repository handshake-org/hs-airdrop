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

There are a few gotchas: we do not allow standard PGP signatures on the
consensus layer. This is done for simplicity and safety. This means that a
regular call to `$ gpg --sign` will not work for handshake airdrop proofs. As
far as SSH keys go, people typically do not sign arbitrary messages with them.

Because of this, we require a special tool to do both the signing and merkle
proof creation.

## Privacy

To preserve privacy for the time being, a 32 byte nonce has been [encrypted
to][nonces] your PGP or SSH key. No one will be able to identify your key
fingerprint in the tree published above until _you_ decide to reveal it
on-chain by decrypting the nonce, creating the proof, and publishing it.

### Just testing (more privacy coming)

Note that this construction is testnet-only. The mainnet construction will
__not__ reveal your existing key to anyone for full privacy on-chain as well.
It's planned to accomplish this by way of HD derivation for EC keys and a much
more complicated setup for RSA keys (which lack any form of HD derivation).

If you want complete privacy, do __not__ reveal your key on testnet! While
impractical, a determined analyst can reserialize your key back into PGP or SSH
format and identify you through your key's fingerprint. They will not be able
to identify you on mainnet, but they _will_ know for certain that you are
present in the tree.

The full list of keys will be destroyed upon mainnet launch. Plaintext nonces
are not saved at all during the generation phase. The ephemeral keys used for
the ECIES key exchanges are also not saved.

## Security

If you're unconfortable having third party software access your PGP and SSH
keys, you are always able to generate this proof on an air-gapped machine. QR
code generation will be added to this tool for convenience (eventually).

Signed tarballs of this software will be released upon mainnet launch.

## Accepted Key Algorithms

To simplify consensus implementation, we only allow the top 3 most popular key
algorithms used on github:

- __RSA__ (1024 to 4096 bit modulus, e <= 33 bits) - See the Handshake paper as
  to why 1024 bit moduli are considered acceptable.
- __Ed25519__
- __P256__ (NIST curve)

Note that while DSA is a popular choice of key in the strongset, we found
30,000 of them to be potentially vulnerable to the [Logjam][logjam] attack, and
as such, must be considered compromised. For this reason, DSA will not be
supported at all.

## Faucet Migration

If you submitted an address to the Handshake faucet, it will be included in the
mainnet merkle tree.

## Disclaimer (WIP)

All a work-in-progress. Many things are subject to change.

## Usage

```
$ hs-airdrop
hs-airdrop v0.0.0

This tool will create the proof necessary to
collect your faucet reward, airdrop reward, or
sponsor reward on the Handshake blockchain.

Usage: $ hs-airdrop [key-file] [key-id] [address] [fee]
       $ hs-airdrop [key-file] [address] [fee]
       $ hs-airdrop [address] [value]
       $ hs-airdrop [address] [value] --sponsor

  [key-file] can be:
    - An SSH private key file.
    - An exported PGP armor keyring (.asc).
    - An exported PGP raw keyring (.pgp/.gpg).

  [key-id] is only necessary for PGP keys.

  [address] must be a Handshake bech32 address.
  [value] must be the coin value awarded to you (in HNS).
  [fee] must be a coin value (in HNS).

  The --sponsor flag is necessary for project sponsors.

  This tool will provide a JSON representation of
  your airdrop proof as well as a base64 string.

  The base64 string must be passed to:
    $ hsd-rpc sendrawclaim "base64-string"
```

## License

MIT License.

- Copyright (c) 2018, Christopher Jeffrey (https://github.com/chjj)
- Copyright (c) 2018, Handshake Contributors (https://github.com/handshake-org)

See LICENSE for more info.

[tree]: https://github.com/handshake-org/hs-tree-data
[nonces]: https://github.com/handshake-org/hs-tree-data/tree/master/nonces
[logjam]: https://en.wikipedia.org/wiki/Logjam_(computer_security)
