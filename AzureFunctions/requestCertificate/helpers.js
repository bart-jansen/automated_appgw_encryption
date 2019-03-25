'use strict';

let util = require('util');

// urlsafe base64 encoding (jose)
function urlBase64Encode(string) {
    return string.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

function b64(str) {
    let buf = util.isBuffer(str) ? str : new Buffer(str);
    return urlBase64Encode(buf.toString('base64'));
}

function getModulus(pem) {
    assert(util.isBuffer(pem));

    let stdout = safe.child_process.execSync('openssl rsa -modulus -noout', { input: pem, encoding: 'utf8' });
    if (!stdout) return null;
    let match = stdout.match(/Modulus=([0-9a-fA-F]+)$/m);
    if (!match) return null;
    return Buffer.from(match[1], 'hex');
}

module.exports = {
    urlBase64Encode, 
    b64,
    getModulus
}