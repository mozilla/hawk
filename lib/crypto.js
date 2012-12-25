// Load modules

var Crypto = require('crypto');
var Url = require('url');


// Declare internals

var internals = {};


// Supported MAC algorithms

exports.algorithms = ['hmac-sha-1', 'hmac-sha-256'];


// Calculate the request MAC

exports.calculateMAC = function (key, algorithm, timestamp, nonce, method, uri, host, port, ext) {

    // Parse request URI

    var url = Url.parse(uri);

    // Construct normalized req string

    var normalized = timestamp + '\n' +
                     nonce + '\n' +
                     method.toUpperCase() + '\n' +
                     url.pathname + (url.search || '') + '\n' +
                     host.toLowerCase() + '\n' +
                     port + '\n' +
                     (ext || '') + '\n';

    // Lookup hash function

    var hashMethod = '';
    switch (algorithm) {

        case 'hmac-sha-1': hashMethod = 'sha1'; break;
        case 'hmac-sha-256': hashMethod = 'sha256'; break;
        default: return '';
    }

    // MAC normalized req string

    var hmac = Crypto.createHmac(hashMethod, key).update(normalized);
    var digest = hmac.digest('base64');
    return digest;
};

