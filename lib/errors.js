'use strict';

class SignError extends Error {
  constructor(msg) {
    super(msg);

    this.type = 'SignError';
    this.name = 'SignError';
    this.code = 'ERR_SIGN';

    if (Error.captureStackTrace)
      Error.captureStackTrace(this, SignError);
  }
}

exports.SignError = SignError;
