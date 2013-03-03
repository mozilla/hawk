// Load modules

var Url = require('url');
var Boom = require('boom');
var Hoek = require('hoek');
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

    var attributes = Utils.parseAuthorizationHeader(request.authorization);
    if (attributes instanceof Error) {
        return callback(attributes);
    }

    // Construct artifacts container

    var artifacts = {
        method: request.method,
        host: request.host,
        port: request.port,
        resource: request.url,
        ts: attributes.ts,
        nonce: attributes.nonce,
        hash: attributes.hash,
        ext: attributes.ext,
        app: attributes.app,
        dlg: attributes.dlg,
        mac: attributes.mac,
        id: attributes.id
    };

    // Verify required header attributes

    if (!attributes.id ||
        !attributes.ts ||
        !attributes.nonce ||
        !attributes.mac) {

        return callback(Boom.badRequest('Missing attributes'), null, artifacts);
    }

    // Check timestamp staleness

    if (Math.abs((attributes.ts * 1000) - now) > (options.timestampSkewSec * 1000)) {
        return callback(Boom.unauthorized('Stale timestamp', 'Hawk', { ts: now }), null, artifacts);
    }

    // Fetch Hawk credentials

    credentialsFunc(attributes.id, function (err, credentials) {

        artifacts.credentials = credentials;

        if (err) {
            return callback(err, credentials || null, artifacts);
        }

        if (!credentials) {
            return callback(Boom.unauthorized('Unknown credentials', 'Hawk'), null, artifacts);
        }

        if (!credentials.key ||
            !credentials.algorithm) {

            return callback(Boom.internal('Invalid credentials'), credentials, artifacts);
        }

        if (Crypto.algorithms.indexOf(credentials.algorithm) === -1) {
            return callback(Boom.internal('Unknown algorithm'), credentials, artifacts);
        }

        // Calculate MAC

        var mac = Crypto.calculateMac('header', artifacts);
        if (!Cryptiles.fixedTimeComparison(mac, attributes.mac)) {
            return callback(Boom.unauthorized('Bad mac', 'Hawk'), credentials, artifacts);
        }

        // Check payload hash

        if (options.payload !== null &&
            options.payload !== undefined) {       // '' is valid

            if (!attributes.hash) {
                return callback(Boom.unauthorized('Missing required payload hash', 'Hawk'), credentials, artifacts);
            }

            var hash = Crypto.calculateHash(options.payload, credentials.algorithm, request.contentType);
            if (!Cryptiles.fixedTimeComparison(hash, attributes.hash)) {
                return callback(Boom.unauthorized('Bad payload hash', 'Hawk'), credentials, artifacts);
            }
        }

        // Check nonce

        options.nonceFunc(attributes.nonce, attributes.ts, function (err) {

            if (err) {
                return callback(Boom.unauthorized('Invalid nonce', 'Hawk'), credentials, artifacts);
            }

            // Successful authentication

            return callback(null, credentials, artifacts);
        });
    });
};


// Validate payload hash

exports.validatePayload = function (payload, credentials, hash, contentType) {

    var calculatedHash = Crypto.calculateHash(payload, credentials.algorithm, contentType);
    return Cryptiles.fixedTimeComparison(calculatedHash, hash);
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
            algorithm: 'sha256'                                 // 'sha1', 'sha256'
        },

        // Optional

        ext: 'application-specific',                        // Application specific data sent via the ext attribute
        timestamp: Date.now(),                              // A pre-calculated timestamp
        nonce: '2334f34f',                                  // A pre-generated nonce
        localtimeOffsetMsec: 400,                           // Time offset to sync with server time (ignored if timestamp provided)
        payload: '{"some":"payload"}',                      // UTF-8 encoded string for body hash generation (ignored if hash provided)
        contentType: 'application/json',                    // Payload content-type (ignored if hash provided)
        hash: 'U4MKKSmiVxk37JCCrAVIjV=',                    // Pre-calculated payload hash
        app: '24s23423f34dx',                               // Oz application id
        dlg: '234sz34tww3sd'                                // Oz delegated-by application id
    }
*/

exports.getAuthorizationHeader = function (uri, method, options) {

    return exports.getAuthorizationRequestHeader(uri, method, options).header;
};


exports.getAuthorizationRequestHeader = function (uri, method, options) {

    var result = {
        header: '',
        artifacts: {}
    };

    // Validate inputs

    if (!uri || (typeof uri !== 'string' && typeof uri !== 'object') ||
        !method || typeof method !== 'string' ||
        !options || typeof options !== 'object') {

        return result;
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
        return result;
    }

    if (Crypto.algorithms.indexOf(credentials.algorithm) === -1) {
        return result;
    }

    // Parse URI

    if (typeof uri === 'string') {
        uri = Url.parse(uri);
    }

    // Calculate signature

    var artifacts = {
        credentials: credentials,
        ts: timestamp,
        nonce: options.nonce || Cryptiles.randomString(6),
        method: method,
        resource: uri.pathname + (uri.search || ''),                            // Maintain trailing '?'
        host: uri.hostname,
        port: uri.port || (uri.protocol === 'http' ? 80 : 443),
        hash: options.hash,
        ext: options.ext,
        app: options.app,
        dlg: options.dlg
    };

    result.artifacts = artifacts;

    // Calculate payload hash

    if (!artifacts.hash &&
        options.hasOwnProperty('payload')) {

        artifacts.hash = Crypto.calculateHash(options.payload, credentials.algorithm, options.contentType);
    }

    var mac = Crypto.calculateMac('header', artifacts);

    // Construct header

    var hasExt = artifacts.ext !== null && artifacts.ext !== undefined && artifacts.ext !== '';       // Other falsey values allowed
    var header = 'Hawk id="' + credentials.id +
                 '", ts="' + artifacts.ts +
                 '", nonce="' + artifacts.nonce +
                 (artifacts.hash ? '", hash="' + artifacts.hash : '') +
                 (hasExt ? '", ext="' + Utils.escapeHeaderAttribute(artifacts.ext) : '') +
                 '", mac="' + mac + '"';

    if (artifacts.app) {
        header += ', app="' + artifacts.app +
                  (artifacts.dlg ? '", dlg="' + artifacts.dlg : '') + '"';
    }

    result.header = header;

    return result;
};


// Generate an Authorization header for a given response

/*
    artifacts: {}                                          // Object received from authenticate(); 'mac', 'hash', and 'ext' - ignored
    options: {
        ext: 'application-specific',                        // Application specific data sent via the ext attribute
        payload: '{"some":"payload"}',                      // UTF-8 encoded string for body hash generation (ignored if hash provided)
        contentType: 'application/json',                    // Payload content-type (ignored if hash provided)
        hash: 'U4MKKSmiVxk37JCCrAVIjV='                     // Pre-calculated payload hash
    }
*/

exports.getAuthorizationResponseHeader = function (artifacts, options) {

    // Prepare inputs

    options = options || {};

    if (!artifacts ||
        typeof artifacts !== 'object' ||
        typeof options !== 'object') {

        return '';
    }

    artifacts = Hoek.clone(artifacts);
    delete artifacts.mac;
    artifacts.hash = options.hash;
    artifacts.ext = options.ext;

    // Validate credentials

    var credentials = artifacts.credentials;
    if (!credentials ||
        !artifacts.id ||
        !credentials.key ||
        !credentials.algorithm) {

        // Invalid credential object
        return '';
    }

    if (Crypto.algorithms.indexOf(credentials.algorithm) === -1) {
        return '';
    }

    // Calculate payload hash

    if (!artifacts.hash &&
        options.hasOwnProperty('payload')) {

        artifacts.hash = Crypto.calculateHash(options.payload, credentials.algorithm, options.contentType);
    }

    var mac = Crypto.calculateMac('response', artifacts);

    // Construct header

    var header = 'Hawk mac="' + mac + '"' +
                 (artifacts.hash ? ', hash="' + artifacts.hash + '"': '');

    if (artifacts.ext !== null &&
        artifacts.ext !== undefined &&
        artifacts.ext !== '') {                       // Other falsey values allowed

        header += ', ext="' + Utils.escapeHeaderAttribute(artifacts.ext) + '"';
    }

    return header;
};


// Validate server response

/*
    req:        node's response object
    artifacts:  object recieved from getAuthorizationRequestHeader()
    payload:    optional payload received
*/

exports.validateResponse = function (req, artifacts, payload) {

    artifacts = Hoek.clone(artifacts);

    // Parse HTTP Authorization header

    var attributes = Utils.parseAuthorizationHeader(req.headers.authorization, ['mac', 'ext', 'hash']);
    if (attributes instanceof Error) {
        return false;
    }

    artifacts.ext = attributes.ext;
    artifacts.hash = attributes.hash;

    var mac = Crypto.calculateMac('response', artifacts);
    if (!Cryptiles.fixedTimeComparison(mac, attributes.mac)) {
        return false;
    }

    if (payload === undefined) {
        return true;
    }

    var calculatedHash = Crypto.calculateHash(payload, artifacts.credentials.algorithm, req.headers['content-type']);
    return Cryptiles.fixedTimeComparison(calculatedHash, attributes.hash);
};

