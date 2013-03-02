// Load modules

var Url = require('url');
var Boom = require('boom');
var Cryptiles = require('cryptiles');
var Sntp = require('sntp');
var Crypto = require('./crypto');
var Utils = require('./utils');
var Uri = require('./uri');


// Declare internals

var internals = {};


// Export sub-modules

exports.crypto = Crypto;
exports.error = exports.Error = Boom;
exports.sntp = Sntp;
exports.uri = Uri;
exports.utils = Utils;


// Hawk authentication

/*
 * req                - node's HTTP request object or an object as follows:
 *
 *                      var request = {
 *                          method: 'GET',
 *                          url: '/resource/4?a=1&b=2',
 *                          host: 'example.com',
 *                          port: 8080,
 *                          authorization: 'Hawk id="dh37fgj492je", ts="1353832234", nonce="j4h3g2", ext="some-app-ext-data", mac="6R4rV5iE+NPoym+WwjeHzjAGXUtLNIxmo1vpMofpLAE="'
 *                      };
 *
 * credentialsFunc    - required function to lookup the set of Hawk credentials based on the provided credentials id.
 *                      The credentials include the MAC key, MAC algorithm, and other attributes (such as username)
 *                      needed by the application. This function is the equivalent of verifying the username and
 *                      password in Basic authentication.
 *
 *                      var credentialsFunc = function (id, callback) {
 *  
 *                          // Lookup credentials in database
 *                          db.lookup(id, function (err, item) {
 *  
 *                              if (err || !item) {
 *                                  return callback(err);
 *                              }
 *  
 *                              var credentials = {
 *                                  // Required
 *                                  key: item.key,
 *                                  algorithm: item.algorithm,
 *                                  // Application specific
 *                                  user: item.user
 *                              };
 *  
 *                              return callback(null, credentials);
 *                          });
 *                      };
 *
 * options:
 * 
 * hostHeaderName       - optional header field name, used to override the default 'Host' header when used
 *                        behind a cache of a proxy. Apache2 changes the value of the 'Host' header while preserving
 *                        the original (which is what the module must verify) in the 'x-forwarded-host' header field.
 *                        Only used when passed a node Http.ServerRequest object.
 *
 * nonceFunc            - optional nonce validation function. The function signature is function(nonce, ts, callback)
 *                        where 'callback' must be called using the signature function(err).
 *
 * timestampSkewSec     - optional number of seconds of permitted clock skew for incoming timestamps. Defaults to 60 seconds.
 *                        Provides a +/- skew which means actual allowed window is double the number of seconds.
 *
 * localtimeOffsetMsec  - optional local clock time offset express in a number of milliseconds (positive or negative).
 *                        Defaults to 0.
 *
 * payload              - optional payload for validation. The client calculates the hash value and includes it via the 'hash'
 *                        header attribute. The server always ensures the value provided has been included in the request
 *                        MAC. When this option is provided, it validates the hash value itself. Validation is done by calculating
 *                        a hash value over the entire payload (assuming it has already be normalized to the same format and
 *                        encoding used by the client to calculate the hash on request). If the payload is not available at the time
 *                        of authentication, the validatePayload() method can be used by passing it the credentials and
 *                        attributes.hash returned in the authenticate callback.
 */

exports.authenticate = function (req, credentialsFunc, options, callback) {

    // Default options

    options.nonceFunc = options.nonceFunc || function (nonce, ts, callback) { return callback(); };         // No validation
    options.timestampSkewSec = options.timestampSkewSec || 60;                                              // 60 seconds

    // Application time

    var now = Utils.now() + (options.localtimeOffsetMsec || 0);

    // Convert node Http request object to a request configuration object

    var request = Utils.parseRequest(req, options);
    if (request instanceof Error) {
        return callback(Boom.badRequest(request.message));
    }

    // Parse HTTP Authorization header

    if (!request.authorization) {
        return callback(Boom.unauthorized(null, 'Hawk', { ts: now }));
    }

    var headerParts = request.authorization.match(/^(\w+)(?:\s+(.*))?$/);       // Header: scheme[ something]
    if (!headerParts) {
        return callback(Boom.badRequest('Invalid header syntax'));
    }

    var scheme = headerParts[1];
    if (scheme.toLowerCase() !== 'hawk') {
        return callback(Boom.unauthorized(null, 'Hawk', { ts: now }));
    }

    var attributesString = headerParts[2];
    if (!attributesString) {
        return callback(Boom.badRequest('Invalid header syntax'));
    }

    var attributes = {};
    var errorMessage = '';
    var verify = attributesString.replace(/(\w+)="([^"\\]*)"\s*(?:,\s*|$)/g, function ($0, $1, $2) {

        // Check valid attribute names

        if (['id', 'ts', 'nonce', 'hash', 'ext', 'mac', 'app', 'dlg'].indexOf($1) === -1) {
            errorMessage = 'Unknown attribute: ' + $1;
            return;
        }

        // Allowed attribute value characters: !#$%&'()*+,-./:;<=>?@[]^_`{|}~ and space, a-z, A-Z, 0-9

        if ($2.match(/^[ \w\!#\$%&'\(\)\*\+,\-\.\/\:;<\=>\?@\[\]\^`\{\|\}~]+$/) === null) {
            errorMessage = 'Bad attribute value: ' + $1;
            return;
        }

        // Check for duplicates

        if (attributes.hasOwnProperty($1)) {
            errorMessage = 'Duplicate attribute: ' + $1;
            return;
        }

        attributes[$1] = $2;
        return '';
    });

    if (verify !== '') {
        return callback(Boom.badRequest(errorMessage || 'Bad header format'));
    }

    // Verify required header attributes

    if (!attributes.id ||
        !attributes.ts ||
        !attributes.nonce ||
        !attributes.mac) {

        return callback(Boom.badRequest('Missing attributes'), null, attributes);
    }

    // Check timestamp staleness

    if (Math.abs((attributes.ts * 1000) - now) > (options.timestampSkewSec * 1000)) {
        return callback(Boom.unauthorized('Stale timestamp', 'Hawk', { ts: now }), null, attributes);
    }

    // Fetch Hawk credentials

    credentialsFunc(attributes.id, function (err, credentials) {

        if (err) {
            return callback(err, credentials || null, attributes);
        }

        if (!credentials) {
            return callback(Boom.unauthorized('Unknown credentials', 'Hawk'), null, attributes);
        }

        if (!credentials.key ||
            !credentials.algorithm) {

            return callback(Boom.internal('Invalid credentials'), credentials, attributes);
        }

        if (Crypto.algorithms.indexOf(credentials.algorithm) === -1) {
            return callback(Boom.internal('Unknown algorithm'), credentials, attributes);
        }

        // Calculate MAC

        var mac = Crypto.calculateMac({
            type: 'header',
            credentials: credentials,
            timestamp: attributes.ts,
            nonce: attributes.nonce,
            method: request.method,
            resource: request.url,/////////////////////////////////////////////////
            host: request.host,
            port: request.port,
            hash: attributes.hash,
            ext: attributes.ext,
            app: attributes.app,
            dlg: attributes.dlg
        });

        if (!Cryptiles.fixedTimeComparison(mac, attributes.mac)) {
            return callback(Boom.unauthorized('Bad mac', 'Hawk'), credentials, attributes);
        }

        // Check payload hash

        if (options.payload !== null &&
            options.payload !== undefined) {       // '' is valid

            if (!attributes.hash) {
                return callback(Boom.unauthorized('Missing required payload hash', 'Hawk'), credentials, attributes);
            }

            var hash = Crypto.calculateHash(options.payload, credentials.algorithm);
            if (!Cryptiles.fixedTimeComparison(hash, attributes.hash)) {
                return callback(Boom.unauthorized('Bad payload hash', 'Hawk'), credentials, attributes);
            }
        }

        // Check nonce

        options.nonceFunc(attributes.nonce, attributes.ts, function (err) {

            if (err) {
                return callback(Boom.unauthorized('Invalid nonce', 'Hawk'), credentials, attributes);
            }

            // Successful authentication

            return callback(null, credentials, attributes);
        });
    });
};


// Generate an Authorization header for a given request

/*
    uri: 'http://example.com/resource?a=b' or object from Url.parse()
    method: HTTP verb (e.g. 'GET', 'POST')
    options: {

        // Required

        credentials: {
            id: 'dh37fgj492je',
            key: 'aoijedoaijsdlaksjdl',
            algorithm: 'sha256'                             // 'sha1', 'sha256'
        },

        // Optional

        ext: 'application-specific',                        // Application specific data sent via the ext attribute
        timestamp: Date.now(),                              // A pre-calculated timestamp
        none: '2334f34f',                                   // A pre-generated nonce
        localtimeOffsetMsec: 400,                           // Time offset to sync with server time (ignored if timestamp provided)
        payload: '{"some":"payload"}',                      // UTF-8 encoded string for body hash generation
        app: '24s23423f34dx',                               // Oz application id
        dlg: '234sz34tww3sd'                                // Oz delegated-by application id
    };
*/

exports.getAuthorizationHeader = function (uri, method, options) {

    // Validate inputs

    if (!uri ||
        (typeof uri !== 'string' && typeof uri !== 'object') ||
        !method ||
        typeof method !== 'string' ||
        !options ||
        typeof options !== 'object') {

        return '';
    }

    // Application time

    var timestamp = options.timestamp || Math.floor((Utils.now() + (options.localtimeOffsetMsec || 0)) / 1000)

    // Validate credentials

    var credentials = options.credentials;
    if (!credentials ||
        !credentials.id ||
        !credentials.key ||
        !credentials.algorithm) {

        // Invalid credential object
        return '';
    }

    if (Crypto.algorithms.indexOf(credentials.algorithm) === -1) {
        return '';
    }

    // Calculate payload hash

    var hash = null;
    if (options.payload !== null &&
        options.payload !== undefined) {

        hash = Crypto.calculateHash(options.payload, credentials.algorithm);
    }

    // Parse URI

    if (typeof uri === 'string') {
        uri = Url.parse(uri);
    }

    // Calculate signature

    var artifacts = {
        type: 'header',
        credentials: credentials,
        timestamp: timestamp,
        nonce: options.nonce || Cryptiles.randomString(6),
        method: method,
        resource: uri.pathname + (uri.search || ''),                            // Maintain trailing '?'
        host: uri.hostname,
        port: uri.port || (uri.protocol === 'http' ? 80 : 443),
        hash: hash,
        ext: options.ext,
        app: options.app,
        dlg: options.dlg
    };

    var mac = Crypto.calculateMac(artifacts);

    // Construct header

    var hasExt = options.ext !== null && options.ext !== undefined && options.ext !== '';       // Other falsey values allowed
    var header = 'Hawk id="' + credentials.id +
                 '", ts="' + artifacts.timestamp +
                 '", nonce="' + artifacts.nonce +
                 (hash ? '", hash="' + hash : '') +
                 (hasExt ? '", ext="' + Utils.escapeHeaderAttribute(options.ext) : '') +
                 '", mac="' + mac + '"';

    if (options.app) {
        header += ', app="' + options.app +
                  (options.dlg ? '", dlg="' + options.dlg : '') + '"';
    }

    return header;
};


// Validate payload hash

exports.validatePayload = function (payload, credentials, hash) {

    var calculatedHash = Crypto.calculateHash(payload, credentials.algorithm);
    return Cryptiles.fixedTimeComparison(calculatedHash, hash);
};

