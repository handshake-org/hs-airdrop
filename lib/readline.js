'use strict';

/* eslint no-use-before-define: "off" */

const assert = require('bsert');
const {StringDecoder} = require('string_decoder');
const readline = require('readline');

async function readLine(prefix = '', secret = false) {
  assert(typeof prefix === 'string');
  assert(typeof secret === 'boolean');

  const {stdin} = process;

  if (!stdin.isTTY || !secret)
    return readLineUnmasked(prefix);

  return readLineMasked(prefix);
}

async function readLineMasked(prefix = '') {
  const decoder = new StringDecoder('utf8');
  const {stdin, stdout} = process;
  stdin.setRawMode(true);
  stdin.resume();

  if (prefix)
    stdout.write(`${prefix}: `);

  let out = '';
  return new Promise((resolve, reject) => {
    const cleanup = () => {
      stdin.removeListener('error', onError);
      stdin.removeListener('data', onData);
      stdin.pause();
      stdin.setRawMode(false);
    };

    const onError = (err) => {
      cleanup();
      reject(err);
    };

    const onData = (data) => {
      if (data.length === 0)
        return;

      switch (data[0]) {
        case 0x5c: { // ^\
          process.exit(1);
          break;
        }

        case 0x03: // ^C
        case 0x04: // ^D
        case 0x0d: { // <CR>
          cleanup();
          stdout.write('\n');
          resolve(out);
          break;
        }

        case 0x7f: { // Backspace
          if (out.length > 0) {
            out = out.slice(0, -1);
          }
          break;
        }

        case 0x1b: { // Escape code
          break;
        }

        default: {
          out += decoder.write(data);

          if (out.length > 4096) {
            cleanup();
            reject(new Error('String too long.'));
          }

          break;
        }
      }
    };

    stdin.on('error', onError);
    stdin.on('data', onData);
  });
}

async function readLineUnmasked(prompt = '') {
  const {stdin, stdout} = process;
  stdin.resume();
  stdin.setEncoding('utf-8');

  return await new Promise((resolve, reject) => {
    const hdlr = (passphrase) => {
      if (passphrase.length > 4096)
        return reject(new Error('String too long.'));

      resolve(passphrase);
    };

    if (stdin.isTTY) {
      const rl = readline.createInterface({
        input: stdin,
        output: stdout,
      });
      rl.question(prompt ? `${prompt}: ` : '', hdlr);
      return;
    }

    let res = '';
    stdin.on('readable', () => {
      let chunk;
      while ((chunk = stdin.read())) {
        res += chunk;
      }
    });

    stdin.on('end', () => hdlr(res));
  });
}

async function readPassphrase() {
  return readLine('Passphrase', true);
}

exports.readLine = readLine;
exports.readPassphrase = readPassphrase;
