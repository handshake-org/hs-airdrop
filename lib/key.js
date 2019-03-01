/* eslint camelcase: 'off' */

'use strict';

const assert = require('bsert');
const bio = require('bufio');
const {bech32} = require('bstring');
const BLAKE2b = require('bcrypto/lib/blake2b');
const SHA256 = require('bcrypto/lib/sha256');
const SHA3 = require('bcrypto/lib/sha3');
const rsa = require('bcrypto/lib/rsa');
const p256 = require('bcrypto/lib/p256');
const ed25519 = require('bcrypto/lib/ed25519');
const ecies = require('bcrypto/lib/ecies');
const pgp = require('bcrypto/lib/pgp');
const random = require('bcrypto/lib/random');
const ssh = require('bcrypto/lib/ssh');
const Goo = require('goosig');
const {RSAPublicKey, RSAPrivateKey} = rsa;
const {PGPPublicKey, SecretKey} = pgp;
const {SSHPublicKey, SSHPrivateKey} = ssh;

/*
 * Goo
 */

const goo = new Goo(Goo.RSA2048, 2, 3);

/*
 * Constants
 */

const keyTypes = {
  RSA: 0,
  GOO: 1,
  P256: 2,
  ED25519: 3,
  ADDRESS: 4
};

const keyTypesByVal = {
  [keyTypes.RSA]: 'RSA',
  [keyTypes.GOO]: 'GOO',
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
    this.C1 = EMPTY;
    this.point = EMPTY;
    this.version = 0;
    this.address = EMPTY;
    this.value = 0;
    this.sponsor = false;
    this.nonce = SHA256.zero;
    this.tweak = null;
  }

  inject(key) {
    assert(key instanceof AirdropKey);
    this.type = key.type;
    this.n = key.n;
    this.e = key.e;
    this.C1 = key.C1;
    this.point = key.point;
    this.version = key.version;
    this.address = key.address;
    this.value = key.value;
    this.sponsor = key.sponsor;
    this.nonce = key.nonce;
    this.tweak = key.tweak;
    return this;
  }

  isRSA() {
    return this.type === keyTypes.RSA;
  }

  isGoo() {
    return this.type === keyTypes.GOO;
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

      case keyTypes.GOO: {
        return this.C1.length === goo.size;
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

  generate() {
    switch (this.type) {
      case keyTypes.RSA: {
        const pub = new RSAPublicKey(this.n, this.e);
        const s_prime = goo.generate();
        const C1 = goo.challenge(s_prime, pub);

        const key = this.clone();
        key.type = keyTypes.GOO;
        key.n = EMPTY;
        key.e = EMPTY;
        key.C1 = C1;
        key.nonce = SHA256.zero;
        key.tweak = s_prime;

        return [s_prime, key];
      }

      case keyTypes.P256: {
        const tweak = random.randomBytes(32);
        tweak[0] &= 0x7f;

        const key = this.clone();
        // TODO: Change this to remove the possibility of RKAs.
        key.point = p256.publicKeyTweakAdd(this.point, tweak);
        key.nonce = SHA3.digest(tweak);
        key.tweak = tweak;

        return [tweak, key];
      }

      case keyTypes.ED25519: {
        const tweak = random.randomBytes(32);

        const key = this.clone();
        // TODO: Change this to remove the possibility of RKAs.
        key.point = ed25519.publicKeyTweakAdd(this.point, tweak);
        key.nonce = SHA3.digest(tweak);
        key.tweak = tweak;

        return [tweak, key];
      }

      default: {
        throw new assert.AssertionError('Invalid key type.');
      }
    }
  }

  applyTweak(tweak) {
    assert(Buffer.isBuffer(tweak));

    switch (this.type) {
      case keyTypes.RSA: {
        assert(tweak.length === 32);

        const s_prime = tweak;
        const pub = new RSAPublicKey(this.n, this.e);
        const C1 = goo.challenge(s_prime, pub);

        this.type = keyTypes.GOO;
        this.n = EMPTY;
        this.e = EMPTY;
        this.C1 = C1;
        this.nonce = SHA256.zero;
        this.tweak = s_prime;

        return this;
      }

      case keyTypes.P256: {
        assert(tweak.length === 32);
        // TODO: Change this to remove the possibility of RKAs.
        this.point = p256.publicKeyTweakAdd(this.point, tweak);
        this.nonce = SHA3.digest(tweak);
        this.tweak = tweak;
        return this;
      }

      case keyTypes.ED25519: {
        assert(tweak.length === 32);
        // TODO: Change this to remove the possibility of RKAs.
        this.point = ed25519.publicKeyTweakAdd(this.point, tweak);
        this.nonce = SHA3.digest(tweak);
        this.tweak = tweak;
        return this;
      }

      default: {
        throw new assert.AssertionError('Invalid key type.');
      }
    }
  }

  applyNonce(tweak) {
    assert(Buffer.isBuffer(tweak));
    assert(tweak.length === 32);

    this.nonce = BLAKE2b.digest(tweak);

    return this;
  }

  verify(msg, sig) {
    assert(Buffer.isBuffer(msg));
    assert(Buffer.isBuffer(sig));

    switch (this.type) {
      case keyTypes.RSA: {
        const key = new RSAPublicKey(this.n, this.e);
        return rsa.verify(SHA256, msg, sig, key);
      }

      case keyTypes.GOO: {
        return goo.verify(msg, sig, this.C1);
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

        return rsa.sign(SHA256, msg, key);
      }

      case keyTypes.GOO: {
        const key = new RSAPrivateKey(
          null,
          null,
          sk.d.data,
          sk.p.data,
          sk.q.data,
          null,
          null,
          sk.qi.data
        );

        rsa.privateKeyCompute(key);

        return goo.sign(msg, this.tweak, key);
      }

      case keyTypes.P256: {
        if (this.tweak) {
          // TODO: Change this to remove the possibility of RKAs.
          // const key = p256.privateKeyTweakAdd(sk.d.data, this.tweak);
          // return p256.sign(msg, key);
          throw new Error('EC signing is currently disallowed on testnet.');
        }
        return p256.sign(msg, sk.d.data);
      }

      case keyTypes.ED25519: {
        if (this.tweak) {
          // TODO: Change this to remove the possibility of RKAs.
          // return ed25519.signTweak(msg, sk.d.data, this.tweak);
          throw new Error('EC signing is currently disallowed on testnet.');
        }
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
        return rsa.sign(SHA256, msg, key);
      }

      case keyTypes.GOO: {
        const key = new RSAPrivateKey(
          sk.n,
          sk.e,
          sk.d,
          sk.p,
          sk.q,
          sk.dp,
          sk.dq,
          sk.qi
        );

        return goo.sign(msg, this.tweak, key);
      }

      case keyTypes.P256: {
        if (this.tweak) {
          // TODO: Change this to remove the possibility of RKAs.
          // const key = p256.privateKeyTweakAdd(sk.key, this.tweak);
          // return p256.sign(msg, key);
          throw new Error('EC signing is currently disallowed on testnet.');
        }
        return p256.sign(msg, sk.key);
      }

      case keyTypes.ED25519: {
        if (this.tweak) {
          // TODO: Change this to remove the possibility of RKAs.
          // return ed25519.signTweak(msg, sk.key, this.tweak);
          throw new Error('EC signing is currently disallowed on testnet.');
        }
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

  encrypt(nonce) {
    assert(Buffer.isBuffer(nonce));

    switch (this.type) {
      case keyTypes.RSA:
      case keyTypes.GOO: {
        const key = new RSAPublicKey(this.n, this.e);
        return goo.encrypt(nonce, key);
      }

      case keyTypes.P256: {
        return ecies.encrypt(p256, SHA256, nonce, this.point);
      }

      case keyTypes.ED25519: {
        return ecies.encrypt(ed25519, SHA256, nonce, this.point);
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
      case keyTypes.RSA:
      case keyTypes.GOO: {
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

        return goo.decrypt(msg, key);
      }

      case keyTypes.P256: {
        return ecies.decrypt(p256, SHA256, msg, sk.d.data);
      }

      case keyTypes.ED25519: {
        return ecies.decrypt(ed25519, SHA256, msg, sk.d.data);
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
        return goo.decrypt(msg, key);
      }

      case keyTypes.P256: {
        return ecies.decrypt(p256, SHA256, msg, sk.key);
      }

      case keyTypes.ED25519: {
        return ecies.decrypt(ed25519, SHA256, msg, sk.key);
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
    return BLAKE2b.digest(bw.render());
  }

  bucket() {
    return this.hash()[0];
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
        size += 32;
        break;
      case keyTypes.GOO:
        size += goo.size;
        break;
      case keyTypes.P256:
        size += 33;
        size += 32;
        break;
      case keyTypes.ED25519:
        size += 32;
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
        bw.writeBytes(this.nonce);
        break;
      case keyTypes.GOO:
        bw.writeBytes(this.C1);
        break;
      case keyTypes.P256:
      case keyTypes.ED25519:
        bw.writeBytes(this.point);
        bw.writeBytes(this.nonce);
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

    return bw;
  }

  read(br) {
    this.type = br.readU8();

    switch (this.type) {
      case keyTypes.RSA: {
        this.n = br.readBytes(br.readU16());
        this.e = br.readBytes(br.readU8());
        this.nonce = br.readBytes(32);
        break;
      }

      case keyTypes.GOO: {
        this.C1 = br.readBytes(goo.size);
        break;
      }

      case keyTypes.P256: {
        this.point = br.readBytes(33);
        this.nonce = br.readBytes(32);
        break;
      }

      case keyTypes.ED25519: {
        this.point = br.readBytes(32);
        this.nonce = br.readBytes(32);
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
            // https://tools.ietf.org/html/draft-koch-eddsa-for-openpgp-00#section-3
            // https://tools.ietf.org/html/rfc4880#section-3.2
            let data = Buffer.from(pk.point.data);

            // Note: the RFC implies big-endian,
            // but these are actually little-endian.
            if (data.length === 33 && data[0] === 0x40)
              data = data.slice(1);

            assert(data.length === 32);

            this.type = keyTypes.ED25519;
            this.point = data;

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
        assert(pk.key.length === 32);
        this.type = keyTypes.ED25519;
        this.point = pk.key;
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
      C1: this.C1.length > 0
        ? this.C1.toString('hex')
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
      nonce: !this.isGoo() && !this.isAddress()
        ? this.nonce.toString('hex')
        : undefined
    };
  }

  fromJSON(json) {
    assert(json && typeof json === 'object');
    assert(typeof json.type === 'string');
    assert(keyTypes.hasOwnProperty(json.type));

    this.type = keyTypes[json.type];

    switch (this.type) {
      case keyTypes.RSA: {
        this.n = parseHex(json.n);
        this.e = parseHex(json.e);
        this.nonce = parseHex(json.nonce, 32);
        break;
      }

      case keyTypes.GOO: {
        this.C1 = parseHex(json.C1);
        break;
      }

      case keyTypes.P256: {
        this.point = parseHex(json.point, 33);
        this.nonce = parseHex(json.nonce, 32);
        break;
      }

      case keyTypes.ED25519: {
        this.point = parseHex(json.point, 32);
        this.nonce = parseHex(json.nonce, 32);
        break;
      }

      case keyTypes.ADDRESS: {
        assert((json.version & 0xff) === json.version);
        assert(Number.isSafeInteger(json.value) && json.value >= 0);
        assert(typeof json.sponsor === 'boolean');
        this.version = json.version;
        this.address = parseHex(json.address);
        this.value = json.value;
        this.sponsor = json.sponsor;
        break;
      }

      default: {
        throw new Error('Unknown key type.');
      }
    }

    return this;
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

function parseHex(str, size) {
  if (size == null)
    size = str.length >>> 1;

  assert(typeof str === 'string');
  assert((size >>> 0) === size);
  assert(str.length / 2 === size);

  const data = Buffer.from(str, 'hex');

  assert(data.length === size);

  return data;
}

/*
 * Expose
 */

module.exports = AirdropKey;
