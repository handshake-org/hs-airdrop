# Handshake Airdrop

Redemption tool for the Handshake network's decentralized airdrop to open
source developers.

## A word of warning

In past weeks, it's become apparent that there are now various scams and
phishing attempts targeting GitHub users. Handshake contributors will _never_
ask you for your private keys, and revealing your private key to _anyone_ is
not necessary to redeem the airdrop.

`hs-airdrop` is the only tool recommended for airdrop redemption. Use anything
else at your own risk.

## How It Works

The Handshake airdrop is a [merkle tree][tree] whose root is added to the
consensus rules of the Handshake protocol. This allows the owner of
an eligible private key to publish a signed merkle proof on chain in order to
redeem their airdrop. If your private key is not found by this tool in the
merkle tree, you are not eligible to claim HNS coins. A blinding factor (or
[nonce][nonces]) was generated for each recipient to allow recipients to clam
their coins anonymously. For a detailed description of the airdrop tree construction process,
read [this comment](https://github.com/handshake-org/hs-airdrop/issues/35#issuecomment-586699876).

Public keys from open source developers were collected in the following ways.
If you are an open source developer that meets the requirements listed below
you may be able to claim __4,246.994314 HNS__ from this airdrop:

* ~250,000 GitHub users with 15 or more followers during the week of __2019-02-04__
were identified and their PGP and SSH keys were downloaded. Out of those
~250,000 users, ~175,000 of them had valid SSH and/or PGP keys at the time of
the merkle tree creation.

* Roughly 30,000 keys from the PGP web-of-trust strong set have also been
included in the tree.

* Hacker News accounts which are linked with Keybase
accounts are included in the tree provided they were ~1.5 years old during the
crawl.


There are a few gotchas:

* If you signed up for the HNS faucet at handshake.org, your GitHub key was
removed from the airdrop. The faucet payouts are recorded in
[proof.json](https://github.com/handshake-org/hs-tree-data/blob/master/proof.json)
and were included in early mainnet blocks already. Restore your seed phrase for
the address you registered on the website and you should have your HNS coins
waiting for you. You can use wallets like
[hsd](https://github.com/handshake-org/hsd) or [Bob](https://bobwallet.io) for this.

* If you met the criteria for a Github airdrop but did not have either a SSH or
PGP key on your Github account at the time of snapshot/tree creation, you do not
have coins allocated to you in the merkle tree.

* We do not allow standard PGP signatures on the
consensus layer. This is done for simplicity and safety. This means that a
regular call to `$ gpg --sign` will not work for handshake airdrop proofs. As
far as SSH keys go, people typically do not sign arbitrary messages with them.
Because of this, we require a special tool to do both the signing and merkle proof
creation.

* The Handshake airdrop tree was constructed ONE time and can not be changed
without a hard fork. If you are not in the airdrop tree, you can not be added
to it retroactively.


## Privacy

An airdrop to GitHub and PGP users presents an obvious privacy concern: GitHub
and PGP keys are generally tied to a person's real identity. While impractical,
a determined analyst could link an on-chain airdrop redemption to a
person's identity.

To solve the privacy issue in a non-interactive way, a 32 byte nonce has been
[encrypted to][nonces] your public key (you will have to grind a file full of
many ciphertexts to find it). For EC keys, this nonce is treated as a scalar
and is used to derive a new key from your old one. For RSA keys, a much more
[complicated setup][goosig] is necessary. In either case, once your _new_ key
is derived using this nonce, you will be able to find its corresponding leaf in
the merkle tree published above.

Publishing a signed airdrop proof using this method _does not_ leak any
information about your actual identity.

The full list of keys will be destroyed upon mainnet launch. Plaintext nonces
are not saved at all during the generation phase. The ephemeral keys used for
the ECIES key exchanges are also not saved.

_NOTE: since block height 52590 (29 January, 2021) the goosig feature is DISABLED.
Read the discussion [here](https://github.com/handshake-org/hsd/pull/305).
If your airdrop key is RSA, you will have to claim with `--bare` (see below)_

## Security

If you're uncomfortable having third party software access your PGP and SSH
keys, you are always able to generate this proof on an air-gapped machine. QR
code generation will be added to this tool for convenience (eventually).

A community member created instructions for
[how to use Docker as a pseudo-airgap](https://github.com/handshake-org/hs-airdrop/issues/106)
when claiming. These instructions may be helpful for you but have not been verified by
project maintainers.

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

## Faucet Participants and Sponsors

This tool also allows for the creation of proofs for faucet recipients and
sponsors. See the usage below for details.

## Usage

If you are unfamiliar with sending blockchain transactions, you can learn what
"transactions" are and what "fees" mean on
[bitcoin.org](https://developer.bitcoin.org/devguide/transactions.html).
The `--fee` argument sends an exact amount of HNS coins (default 0.1 HNS) to the
Handshake network to include your claim into the blockchain. You will receive
4,246.994314 HNS coins (minus fee amount) to your address.

The passphrase requested during the claiming process is for decrypting your SSH/PGP key.

```
$ hs-airdrop -h

  hs-airdrop (v0.7.0)

  This tool will create the proof necessary to
  collect your faucet reward, airdrop reward, or
  sponsor reward on the Handshake blockchain.

  Usage: $ hs-airdrop [key-file] [id] [addr] [options]
         $ hs-airdrop [key-file] [addr] [options]
         $ hs-airdrop [addr]

  Options:

    -v, --version         output the version number
    -b, --bare            redeem airdrop publicly (i.e. without goosig)
    -f, --fee <amount>    set fee for redemption (default: 0.1)
    -d, --data <path>     data directory for cache (default: ~/.hs-tree-data)
    -h, --help            output usage information

  [key-file] can be:

    - An SSH private key file.
    - An exported PGP armor keyring (.asc).
    - An exported PGP raw keyring (.pgp/.gpg).

  [id] is only necessary for PGP keys.

  [addr] must be a Handshake bech32 address.

  The --bare flag will use your existing public key.
  This is not recommended as it makes you identifiable
  on-chain.

  This tool will provide a JSON representation of
  your airdrop proof as well as a base64 string.

  The base64 string must be passed to:
    $ hsd-rpc sendrawairdrop "base64-string"

  Examples:

    $ hs-airdrop ~/.gnupg/secring.gpg 0x12345678 hs1q5z7yyk8xrh4quqg3kw498ngy7hnd4sruqyxnxd -f 0.5
    $ hs-airdrop ~/.ssh/id_rsa hs1q5z7yyk8xrh4quqg3kw498ngy7hnd4sruqyxnxd -f 0.5
    $ hs-airdrop ~/.ssh/id_rsa hs1q5z7yyk8xrh4quqg3kw498ngy7hnd4sruqyxnxd -f 0.5 --bare
    $ hs-airdrop hs1q5z7yyk8xrh4quqg3kw498ngy7hnd4sruqyxnxd
```

## Update: Since block height 52590 (29 January, 2021) the goosig feature is DISABLED.

Read the discussion [here](https://github.com/handshake-org/hsd/pull/305).
If your airdrop key is RSA, you **MUST** generate your claim with `--bare`.
Otherwise, you will get the error [`bad-goosig-disabled`](https://github.com/handshake-org/hs-airdrop/issues/131).

### Notes

Note that if you ran `hs-airdrop` before mainnet, you will need to upgrade to
the latest version of hs-airdrop and clear the cache (`rm -rf ~/.hs-tree-data`).
The usual error thrown in this case is `Invalid checksum: tree.bin`.

The JSON returned by this tool will include your HNS address encoded as separate
hash and version values. These values can be
[encoded back into an HNS address](https://github.com/handshake-org/hs-airdrop/issues/36)
for verification before broadcast.

Users have occasionally reported issues downloading the tree data from GitHub.
If you get an error like the following, you may just need to wait a few minutes
and try again:

```
Attempting to create proof.
This may take a bit.
Decrypting nonce...
Downloading: https://github.com/handshake-org/hs-tree-data/raw/master/nonces/111.bin...
Error: Client network socket disconnected before secure TLS connection was established
at TLSSocket.onConnectEnd (_tls_wrap.js:1084:19)
at Object.onceWrapper (events.js:273:13)
at TLSSocket.emit (events.js:187:15)
at endReadableNT (_stream_readable.js:1085:12)
at process._tickCallback (internal/process/next_tick.js:63:19)
```


## License

MIT License.

- Copyright (c) 2018-2020, Christopher Jeffrey (https://github.com/chjj)
- Copyright (c) 2018-2020, Handshake Contributors (https://github.com/handshake-org)

See LICENSE for more info.

[tree]: https://github.com/handshake-org/hs-tree-data
[nonces]: https://github.com/handshake-org/hs-tree-data/tree/master/nonces
[goosig]: https://github.com/handshake-org/goosig
