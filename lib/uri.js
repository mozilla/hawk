// Load modules

var Url = require('url');
var Crypto = require('./crypto');
var Err = require('./error');
var Utils = require('./utils');


// Declare internals

var internals = {};


// Hawk authentication

/*
 * Arguments and options are the same as index.js with the exception that the only supported options are:
 * 'hostHeaderName', 'localtimeOffsetMsec'
 */

exports.authenticate = function (req, credentialsFunc, options, callback) {

    // Application time

    var now = Date.now() + (options.localtimeOffsetMsec || 0);

    // Verify method is GET

    if (req.method !== 'GET' &&
        req.method !== 'HEAD') {

        return callback(Err.unauthorized('Invalid method'));
    }

    // Obtain host and port information

    var host = Utils.parseHost(req, options.hostHeaderName);
    if (!host) {
        return callback(Err.badRequest('Invalid Host header'));
    }

    // Extract bewit

    //                             1     2             3           4     
    var resource = req.url.match(/^(\/.*)([\?&])bewit\=([^&$]+)(?:&(.+))?$/);
    if (!resource) {
        return callback(Err.unauthorized('Missing bewit'));
    }

    // Parse bewit

    var bewitString = Utils.base64urlDecode(resource[3]);
    if (bewitString instanceof Error) {
        return callback(Err.badRequest('Invalid bewit encoding'));
    }

    // Bewit format: id\exp\mac\ext

    var bewitParts = bewitString.split('\\');
    if (!bewitParts ||
        bewitParts.length !== 4) {

        return callback(Err.badRequest('Invalid bewit structure'));
    }

    var bewit = {
        id: bewitParts[0],
        exp: parseInt(bewitParts[1], 10),
        mac: bewitParts[2],
        ext: bewitParts[3] || ''
    };

    if (!bewit.id ||
        !bewit.exp ||
        !bewit.mac) {

        return callback(Err.badRequest('Missing bewit attributes'));
    }

    // Construct URL without bewit

    var url = resource[1];
    if (resource[4]) {
        url += resource[2] + resource[4];
    }

    // Check expiration

    if (bewit.exp * 1000 <= now) {
        return callback(Err.unauthorized('Access expired'), null, bewit.ext);
    }

    // Fetch Hawk credentials

    credentialsFunc(bewit.id, function (err, credentials) {

        if (err) {
            return callback(err, credentials || null, bewit.ext);
        }

        if (!credentials) {
            return callback(Err.unauthorized('Unknown credentials'), null, bewit.ext);
        }

        if (!credentials.key ||
            !credentials.algorithm) {

            return callback(Err.internal('Invalid credentials'), credentials, bewit.ext);
        }

        if (Crypto.algorithms.indexOf(credentials.algorithm) === -1) {
            return callback(Err.internal('Unknown algorithm'), credentials, bewit.ext);
        }

        // Calculate MAC

        var mac = Crypto.calculateMAC({
            header: 'bewit',
            key: credentials.key,
            algorithm: credentials.algorithm,
            timestamp: bewit.exp,
            nonce: '',
            method: 'GET',
            uri: url,
            host: host.name,
            port: host.port,
            ext: bewit.ext
        });

        if (!Utils.fixedTimeComparison(mac, bewit.mac)) {
            return callback(Err.unauthorized('Bad mac'), credentials, bewit.ext);
        }

        // Successful authentication

        return callback(null, credentials, bewit.ext);
    });
};


// Generate a bewit value for a given URI

/*
 * credentials is an object with the following keys: 'id, 'key', 'algorithm'.
 * options is an object with the following optional keys: 'ext', 'localtimeOffsetMsec'
 */

exports.getBewit = function (credentials, uri, host, port, ttlSec, options) {

    options = options || {};
    options.ext = (options.ext === null || options.ext === undefined ? '' : options.ext);       // Zero is valid value

    // Application time

    var now = Date.now() + (options.localtimeOffsetMsec || 0);

    // Check request

    if (!credentials.id ||
        !credentials.key ||
        !credentials.algorithm) {

        // Invalid credential object
        return '';
    }

    // Calculate signature

    var exp = Math.floor(now / 1000) + ttlSec;
    var mac = Crypto.calculateMAC({
        header: 'bewit',
        key: credentials.key,
        algorithm: credentials.algorithm,
        timestamp: exp,
        nonce: '',
        method: 'GET',
        uri: uri,
        host: host,
        port: port,
        ext: options.ext
    });

    if (!mac) {
        return '';
    }

    // Construct bewit: id\exp\mac\ext

    var bewit = credentials.id + '\\' + exp + '\\' + mac + '\\' + options.ext;
    return Utils.base64urlEncode(bewit);
};


