// Load modules

var Crypto = require('crypto');
var Url = require('url');


// Declare internals

var internals = {};


// MAC normalization format version

exports.headerVersion = '1';                        // Prevent comparison of mac values generated with different normalized string formats


// Supported MAC algorithms

exports.algorithms = ['hmac-sha-1', 'hmac-sha-256'];


// Calculate the request MAC

/*
    options = {
        type: 'header',                             // 'header', 'bewit'
        key: 'aoijedoaijsdlaksjdl',
        algorithm: 'hmac-sha-256',                  // 'hmac-sha-1', 'hmac-sha-256'
        timestamp: 1357718381034,
        nonce: 'd3d345f',
        method: 'GET',
        uri: '/resource?a=1&b=2',
        host: 'example.com',
        port: 8080,
        ext: 'app-specific-data'
    };
*/

exports.calculateMAC = function (options) {

    var normalized = exports.generateNormalizedString(options);

    // Lookup hash function

    var hashMethod = '';
    switch (options.algorithm) {

        case 'hmac-sha-1': hashMethod = 'sha1'; break;
        case 'hmac-sha-256': hashMethod = 'sha256'; break;
        default: return '';
    }

    // MAC normalized req string

    var hmac = Crypto.createHmac(hashMethod, options.key).update(normalized);
    var digest = hmac.digest('base64');
    return digest;
};


exports.generateNormalizedString = function (options) {

    // Parse request URI

    var url = Url.parse(options.uri);

    // Construct normalized req string

    var normalized = 'hawk.' + exports.headerVersion + '.' + options.type + '\n' +
                     options.timestamp + '\n' +
                     options.nonce + '\n' +
                     options.method.toUpperCase() + '\n' +
                     url.pathname + (url.search || '') + '\n' +                     // Maintain trailing ?
                     options.host.toLowerCase() + '\n' +
                     options.port + '\n' +
                     (options.ext || '') + '\n';

    return normalized;
};
