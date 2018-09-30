'use strict';

const assert = require('bsert');
const bio = require('bufio');
const {bech32} = require('bstring');
const blake2b = require('bcrypto/lib/blake2b');
const sha256 = require('bcrypto/lib/sha256');
const rsa = require('bcrypto/lib/rsa');
const p256 = require('bcrypto/lib/p256');
const ed25519 = require('bcrypto/lib/ed25519');
const ecies = require('bcrypto/lib/ecies');
const pgp = require('bcrypto/lib/pgp');
const ssh = require('bcrypto/lib/ssh');
const {RSAPublicKey, RSAPrivateKey} = rsa;
const {PGPPublicKey, SecretKey} = pgp;
const {SSHPublicKey, SSHPrivateKey} = ssh;

/*
 * Constants
 */

const keyTypes = {
  RSA: 0,
  P256: 1,
  ED25519: 2,
  ADDRESS: 3
};

const keyTypesByVal = {
  [keyTypes.RSA]: 'RSA',
  [keyTypes.P256]: 'P256',
  [keyTypes.ED25519]: 'ED25519',
  [keyTypes.ADDRESS]: 'ADDRESS'
};

const EMPTY = Buffer.alloc(0);

/**
 * AirdropKey
 */

class AirdropKey extends bio.Struct {
  constructor() {
    super();
    this.type = keyTypes.RSA;
    this.n = EMPTY;
    this.e = EMPTY;
    this.point = EMPTY;
    this.version = 0;
    this.address = EMPTY;
    this.value = 0;
    this.sponsor = false;
    this.nonce = sha256.zero;
  }

  isRSA() {
    return this.type === keyTypes.RSA;
  }

  isP256() {
    return this.type === keyTypes.P256;
  }

  isED25519() {
    return this.type === keyTypes.ED25519;
  }

  isAddress() {
    return this.type === keyTypes.ADDRESS;
  }

  validate() {
    switch (this.type) {
      case keyTypes.RSA: {
        const key = new RSAPublicKey(this.n, this.e);
        const bits = key.bits();

        // Allow 1024 bit RSA for now.
        // We can softfork out later.
        if (bits < 1024 || bits > 4096)
          return false;

        return rsa.publicKeyVerify(key);
      }

      case keyTypes.P256: {
        return p256.publicKeyVerify(this.point);
      }

      case keyTypes.ED25519: {
        return ed25519.publicKeyVerify(this.point);
      }

      case keyTypes.ADDRESS: {
        return true;
      }

      default: {
        throw new assert.AssertionError('Invalid key type.');
      }
    }
  }

  verify(msg, sig) {
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(sig));

    switch (this.type) {
      case keyTypes.RSA: {
        const key = new RSAPublicKey(this.n, this.e);
        return rsa.verifyPSS(sha256, msg, sig, key);
      }

      case keyTypes.P256: {
        return p256.verify(msg, sig, this.point);
      }

      case keyTypes.ED25519: {
        return ed25519.verify(msg, sig, this.point);
      }

      case keyTypes.ADDRESS: {
        return true;
      }

      default: {
        throw new assert.AssertionError('Invalid key type.');
      }
    }
  }

  sign(msg, sk) {
    if (sk instanceof SecretKey)
      return this.signPGP(msg, sk);
    return this.signSSH(msg, sk);
  }

  signPGP(msg, sk) {
    assert(Buffer.isBuffer(msg));
    assert(sk instanceof SecretKey);

    switch (this.type) {
      case keyTypes.RSA: {
        const key = new RSAPrivateKey(
          this.n,
          this.e,
          sk.d.data,
          sk.p.data,
          sk.q.data,
          null,
          null,
          sk.qi.data
        );

        rsa.privateKeyCompute(key);

        return rsa.signPSS(sha256, msg, key);
      }

      case keyTypes.P256: {
        return p256.sign(msg, sk.d.data);
      }

      case keyTypes.ED25519: {
        return ed25519.sign(msg, sk.d.data);
      }

      case keyTypes.ADDRESS: {
        return null;
      }

      default: {
        throw new assert.AssertionError('Invalid key type.');
      }
    }
  }

  signSSH(msg, sk) {
    assert(Buffer.isBuffer(msg));
    assert(sk instanceof SSHPrivateKey);

    switch (this.type) {
      case keyTypes.RSA: {
        const key = new RSAPrivateKey(
          this.n,
          this.e,
          sk.d,
          sk.p,
          sk.q,
          sk.dp,
          sk.dq,
          sk.qi
        );
        return rsa.signPSS(sha256, msg, key);
      }

      case keyTypes.P256: {
        return p256.sign(msg, sk.key);
      }

      case keyTypes.ED25519: {
        return ed25519.sign(msg, sk.key);
      }

      case keyTypes.ADDRESS: {
        return null;
      }

      default: {
        throw new assert.AssertionError('Invalid key type.');
      }
    }
  }

  encrypt(msg) {
    assert(Buffer.isBuffer(msg));

    switch (this.type) {
      case keyTypes.RSA: {
        const key = new RSAPublicKey(this.n, this.e);
        return rsa.encryptOAEP(sha256, msg, key);
      }

      case keyTypes.P256: {
        return ecies.encrypt(p256, sha256, msg, this.point);
      }

      case keyTypes.ED25519: {
        return ecies.encrypt(ed25519, sha256, msg, this.point);
      }

      case keyTypes.ADDRESS: {
        throw new Error('Cannot encrypt to address.');
      }

      default: {
        throw new assert.AssertionError('Invalid key type.');
      }
    }
  }

  decrypt(msg, sk) {
    if (sk instanceof SecretKey)
      return this.decryptPGP(msg, sk);
    return this.decryptSSH(msg, sk);
  }

  decryptPGP(msg, sk) {
    assert(Buffer.isBuffer(msg));
    assert(sk instanceof SecretKey);

    switch (this.type) {
      case keyTypes.RSA: {
        const key = new RSAPrivateKey(
          this.n,
          this.e,
          sk.d.data,
          sk.p.data,
          sk.q.data,
          null,
          null,
          sk.qi.data
        );

        rsa.privateKeyCompute(key);

        return rsa.decryptOAEP(sha256, msg, key);
      }

      case keyTypes.P256: {
        return ecies.decrypt(p256, sha256, msg, sk.d.data);
      }

      case keyTypes.ED25519: {
        return ecies.decrypt(ed25519, sha256, msg, sk.d.data);
      }

      case keyTypes.ADDRESS: {
        throw new Error('Cannot encrypt to address.');
      }

      default: {
        throw new assert.AssertionError('Invalid key type.');
      }
    }
  }

  decryptSSH(msg, sk) {
    assert(Buffer.isBuffer(msg));
    assert(sk instanceof SSHPrivateKey);

    switch (this.type) {
      case keyTypes.RSA: {
        const key = new RSAPrivateKey(
          this.n,
          this.e,
          sk.d,
          sk.p,
          sk.q,
          sk.dp,
          sk.dq,
          sk.qi
        );
        return rsa.decryptOAEP(sha256, msg, key);
      }

      case keyTypes.P256: {
        return ecies.decrypt(p256, sha256, msg, sk.key);
      }

      case keyTypes.ED25519: {
        return ecies.decrypt(ed25519, sha256, msg, sk.key);
      }

      case keyTypes.ADDRESS: {
        throw new Error('Cannot encrypt to address.');
      }

      default: {
        throw new assert.AssertionError('Invalid key type.');
      }
    }
  }

  hash() {
    const bw = bio.pool(this.getSize());
    this.write(bw);
    return blake2b.digest(bw.render());
  }

  getSize() {
    let size = 0;

    size += 1;

    switch (this.type) {
      case keyTypes.RSA:
        assert(this.n.length <= 0xffff);
        assert(this.e.length <= 0xff);
        size += 2;
        size += this.n.length;
        size += 1;
        size += this.e.length;
        break;
      case keyTypes.P256:
        size += 33;
        break;
      case keyTypes.ED25519:
        size += 32;
        break;
      case keyTypes.ADDRESS:
        size += 1;
        size += 1;
        size += this.address.length;
        size += 8;
        size += 1;
        break;
      default:
        throw new assert.AssertionError('Invalid key type.');
    }

    size += 32;

    return size;
  }

  write(bw) {
    bw.writeU8(this.type);

    switch (this.type) {
      case keyTypes.RSA:
        bw.writeU16(this.n.length);
        bw.writeBytes(this.n);
        bw.writeU8(this.e.length);
        bw.writeBytes(this.e);
        break;
      case keyTypes.P256:
      case keyTypes.ED25519:
        bw.writeBytes(this.point);
        break;
      case keyTypes.ADDRESS:
        bw.writeU8(this.version);
        bw.writeU8(this.address.length);
        bw.writeBytes(this.address);
        bw.writeU64(this.value);
        bw.writeU8(this.sponsor ? 1 : 0);
        break;
      default:
        throw new assert.AssertionError('Invalid key type.');
    }

    bw.writeBytes(this.nonce);

    return bw;
  }

  read(br) {
    this.type = br.readU8();

    switch (this.type) {
      case keyTypes.RSA: {
        this.n = br.readBytes(br.readU16());
        this.e = br.readBytes(br.readU8());
        break;
      }

      case keyTypes.P256: {
        this.point = br.readBytes(33);
        break;
      }

      case keyTypes.ED25519: {
        this.point = br.readBytes(32);
        break;
      }

      case keyTypes.ADDRESS: {
        this.version = br.readU8();
        this.address = br.readBytes(br.readU8());
        this.value = br.readU64();
        this.sponsor = br.readU8() === 1;
        break;
      }

      default: {
        throw new Error('Unknown key type.');
      }
    }

    this.nonce = br.readBytes(32);

    return this;
  }

  fromPGP(pk) {
    assert(pk instanceof PGPPublicKey);

    switch (pk.algorithm) {
      case pgp.keyTypes.RSA:
      case pgp.keyTypes.RSA_ENCRYPT_ONLY:
      case pgp.keyTypes.RSA_SIGN_ONLY: {
        this.type = keyTypes.RSA;
        this.n = trimZeroes(pk.n.data);
        this.e = trimZeroes(pk.e.data);
        break;
      }

      case pgp.keyTypes.ECDH:
      case pgp.keyTypes.ECDSA:
      case pgp.keyTypes.EDDSA: {
        switch (pk.curve) {
          case pgp.curveTypes.P256: {
            this.type = keyTypes.P256;
            this.point = p256.publicKeyConvert(pk.point.data, true);
            break;
          }
          case pgp.curveTypes.ED25519: {
            assert(pk.point.data.length === 32);
            this.type = keyTypes.ED25519;
            this.point = pk.point.data;
            break;
          }
          default: {
            throw new Error('Unsupported algorithm.');
          }
        }
        break;
      }

      default: {
        throw new Error('Unsupported algorithm.');
      }
    }

    return this;
  }

  fromSSH(pk) {
    assert((pk instanceof SSHPublicKey)
        || (pk instanceof SSHPrivateKey));

    switch (pk.type) {
      case ssh.keyTypes.RSA: {
        this.type = keyTypes.RSA;
        this.n = trimZeroes(pk.n);
        this.e = trimZeroes(pk.e);
        break;
      }

      case ssh.keyTypes.P256: {
        this.type = keyTypes.P256;
        this.point = p256.publicKeyConvert(pk.point, true);
        break;
      }

      case ssh.keyTypes.ED25519: {
        assert(pk.point.length === 32);
        this.type = keyTypes.ED25519;
        this.point = pk.point;
        break;
      }

      default: {
        throw new Error('Unsupported algorithm.');
      }
    }

    return this;
  }

  fromAddress(addr, value, sponsor = false) {
    assert(typeof addr === 'string');
    assert(Number.isSafeInteger(value) && value >= 0);
    assert(typeof sponsor === 'boolean');

    const data = bech32.decode(addr);

    assert(data.hrp === 'hs'
        || data.hrp === 'ts'
        || data.hrp === 'rs');
    assert(data.version === 0);
    assert(data.hash.length === 20
        || data.hash.length === 32);

    this.type = keyTypes.ADDRESS;
    this.version = data.version;
    this.address = data.hash;
    this.value = value;
    this.sponsor = sponsor;

    return this;
  }

  getJSON() {
    return {
      type: keyTypesByVal[this.type] || 'UNKNOWN',
      n: this.n.length > 0
        ? this.n.toString('hex')
        : undefined,
      e: this.e.length > 0
        ? this.e.toString('hex')
        : undefined,
      point: this.point.length > 0
        ? this.point.toString('hex')
        : undefined,
      version: this.address.length > 0
        ? this.version
        : undefined,
      address: this.address.length > 0
        ? this.address.toString('hex')
        : undefined,
      value: this.value || undefined,
      sponsor: this.value
        ? this.sponsor
        : undefined,
      nonce: this.nonce.toString('hex')
    };
  }

  static fromPGP(pk) {
    return new this().fromPGP(pk);
  }

  static fromSSH(pk) {
    return new this().fromSSH(pk);
  }

  static fromAddress(addr, value, sponsor) {
    return new this().fromAddress(addr, value, sponsor);
  }
}

/*
 * Static
 */

AirdropKey.keyTypes = keyTypes;
AirdropKey.keyTypesByVal = keyTypesByVal;

/*
 * Helpers
 */

function trimZeroes(buf) {
  assert(Buffer.isBuffer(buf));

  if (buf.length === 0)
    return Buffer.alloc(1, 0x00);

  if (buf[0] !== 0x00)
    return buf;

  for (let i = 1; i < buf.length; i++) {
    if (buf[i] !== 0x00)
      return buf.slice(i);
  }

  return buf.slice(-1);
}

/*
 * Expose
 */

module.exports = AirdropKey;
