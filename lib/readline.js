'use strict';

/* eslint no-use-before-define: "off" */

const assert = require('bsert');
const {StringDecoder} = require('string_decoder');

async function readLine(prefix = '', secret = false) {
  assert(typeof prefix === 'string');
  assert(typeof secret === 'boolean');

  const {stdin, stdout} = process;
  const decoder = new StringDecoder('utf8');

  let out = '';

  stdin.setRawMode(true);
  stdin.resume();

  if (prefix)
    stdout.write(`${prefix} `);

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
            if (!secret)
              stdout.write('\x1b[D \x1b[D');
            out = out.slice(0, -1);
          }
          break;
        }

        case 0x1b: { // Escape code
          break;
        }

        default: {
          const str = decoder.write(data);

          if (!secret)
            stdout.write(str, 'utf8');

          out += str;

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

async function readPassphrase() {
  return readLine('Passphrase:', true);
}

exports.readLine = readLine;
exports.readPassphrase = readPassphrase;
