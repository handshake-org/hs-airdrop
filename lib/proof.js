'use strict';

const assert = require('bsert');
const bio = require('bufio');
const blake2b = require('bcrypto/lib/blake2b');
const sha256 = require('bcrypto/lib/sha256');
const merkle = require('bcrypto/lib/mrkl');
const AirdropKey = require('./key');
const {keyTypes} = AirdropKey;

/*
 * Constants
 */

const EMPTY = Buffer.alloc(0);
const AIRDROP_REWARD = 4662598321;
const SPONSOR_FEE = 500e6;
const RECIPIENT_FEE = 100e6;
const TREE_DEPTH = 18;
const MAX_SUBDEPTH = 5;
const TREE_LEAVES = 204404;
const SUBTREE_LEAVES = 30;

/**
 * AirdropProof
 */

class AirdropProof extends bio.Struct {
  constructor() {
    super();
    this.index = 0;
    this.proof = [];
    this.subindex = 0;
    this.subproof = [];
    this.key = EMPTY;
    this.version = 0;
    this.address = EMPTY;
    this.fee = 0;
    this.signature = EMPTY;
  }

  getSize(sighash = false) {
    let size = 0;

    size += 4;
    size += 1;
    size += this.proof.length * 32;
    size += 1;
    size += 1;
    size += this.subproof.length * 32;
    size += bio.sizeVarBytes(this.key);
    size += 1;
    size += 1;
    size += this.address.length;
    size += bio.sizeVarint(this.fee);

    if (!sighash)
      size += bio.sizeVarBytes(this.signature);

    return size;
  }

  write(bw, sighash = false) {
    bw.writeU32(this.index);
    bw.writeU8(this.proof.length);

    for (const hash of this.proof)
      bw.writeBytes(hash);

    bw.writeU8(this.subindex);
    bw.writeU8(this.subproof.length);

    for (const hash of this.subproof)
      bw.writeBytes(hash);

    bw.writeVarBytes(this.key);
    bw.writeU8(this.version);
    bw.writeU8(this.address.length);
    bw.writeBytes(this.address);
    bw.writeVarint(this.fee);

    if (!sighash)
      bw.writeVarBytes(this.signature);

    return bw;
  }

  read(br) {
    this.index = br.readU32();

    const count = br.readU8();
    assert(count <= TREE_DEPTH);

    for (let i = 0; i < count; i++) {
      const hash = br.readBytes(32);
      this.proof.push(hash);
    }

    this.subindex = br.readU8();

    const total = br.readU8();
    assert(total <= MAX_SUBDEPTH);

    for (let i = 0; i < total; i++) {
      const hash = br.readBytes(32);
      this.subproof.push(hash);
    }

    this.key = br.readVarBytes();
    assert(this.key.length > 0);

    this.version = br.readU8();

    assert(this.version <= 31);

    const size = br.readU8();
    assert(size >= 2 && size <= 40);

    this.address = br.readBytes(size);
    this.fee = br.readVarint();
    this.signature = br.readVarBytes();

    return this;
  }

  verifyMerkle(expect) {
    assert(Buffer.isBuffer(expect));

    const {subproof, subindex} = this;
    const {proof, index} = this;

    if (subproof.length > MAX_SUBDEPTH)
      return false;

    if (proof.length > TREE_DEPTH)
      return false;

    if (subindex >= SUBTREE_LEAVES)
      return false;

    if (index >= TREE_LEAVES)
      return false;

    const leaf = blake2b.digest(this.key);
    const subroot = merkle.deriveRoot(blake2b, leaf, subproof, subindex);
    const root = merkle.deriveRoot(blake2b, subroot, proof, index);

    return root.equals(expect);
  }

  signatureHash() {
    const size = this.getSize(true);
    const bw = bio.pool(size);

    this.write(bw, true);

    return sha256.digest(bw.render());
  }

  getKey() {
    try {
      return AirdropKey.decode(this.key);
    } catch (e) {
      return null;
    }
  }

  verifySignature() {
    const key = this.getKey();

    if (!key)
      return false;

    if (key.isAddress()) {
      const fee = key.sponsor
        ? SPONSOR_FEE
        : RECIPIENT_FEE;

      return this.version === key.version
          && this.address.equals(key.address)
          && this.fee === fee
          && this.signature.length === 0;
    }

    const msg = this.signatureHash();

    return key.verify(msg, this.signature);
  }

  isAddress() {
    if (this.key.length === 0)
      return false;

    return this.key[0] === keyTypes.ADDRESS;
  }

  getValue() {
    if (!this.isAddress())
      return AIRDROP_REWARD;

    const key = this.getKey();

    if (!key)
      return 0;

    return key.value;
  }

  verify(expect) {
    if (this.key.length === 0)
      return false;

    if (this.version > 31)
      return false;

    if (this.address.length < 2 || this.address.length > 40)
      return false;

    if (this.fee > this.getValue())
      return false;

    if (!this.verifyMerkle(expect))
      return false;

    if (!this.verifySignature())
      return false;

    return true;
  }

  sign(key, priv) {
    assert(key instanceof AirdropKey);
    assert(priv);

    const msg = this.signatureHash();

    this.signature = key.sign(msg, priv);

    return this;
  }

  getJSON() {
    const key = this.getKey();

    return {
      index: this.index,
      proof: this.proof.map(h => h.toString('hex')),
      subindex: this.subindex,
      subproof: this.subproof.map(h => h.toString('hex')),
      key: key ? key.toJSON() : null,
      version: this.version,
      address: this.address.toString('hex'),
      fee: this.fee,
      signature: this.signature.toString('hex')
    };
  }
}

/*
 * Expose
 */

module.exports = AirdropProof;
