// Load modules

var Crypto = require('./crypto');
var Err = require('./error');
var Utils = require('./utils');
var Uri = require('./uri');


// Declare internals

var internals = {};


// Export sub-modules

exports.crypto = Crypto;
exports.error = exports.Error = Err;
exports.uri = Uri;
exports.utils = Utils;


// Hawk authentication

/*
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
 * Options:
 * 
 * hostHeaderName       - optional header field name, used to override the default 'Host' header when used
 *                        behind a cache of a proxy. Apache2 changes the value of the 'Host' header while preserving
 *                        the original (which is what the module must verify) in the 'x-forwarded-host' header field.
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
 * ntp                  - optional hostname of the ntp server used to synchronize time between the client and the server. The
 *                        ntp server name is included when the client's timestamp is stale along with the server's
 *                        current timestamp. This allows browser-based clients to sync their application clock directly
 *                        with the server, while native clients can be smarter about managing time sync and caching
 *                        multiple clock offsets using the ntp server value provided. Defaults to 'pool.ntp.org'.
 */

exports.authenticate = function (req, credentialsFunc, options, callback) {

    // Default options

    options.nonceFunc = options.nonceFunc || function (nonce, ts, callback) { return callback(); };         // No validation
    options.timestampSkewSec = options.timestampSkewSec || 60;                                              // 60 seconds
    options.ntp = options.ntp || 'pool.ntp.org';                                                            // pool.ntp.org

    // Application time
    
    var now = Date.now() + (options.localtimeOffsetMsec || 0);

    // Obtain host and port information

    var host = Utils.parseHost(req, options.hostHeaderName);
    if (!host) {
        return callback(Err.badRequest('Invalid Host header'));
    }

    // Parse HTTP Authorization header

    if (!req.headers.authorization) {
        return callback(Err.unauthorizedWithTs('', now, options.ntp));
    }

    var headerParts = req.headers.authorization.match(/^(\w+)(?:\s+(.*))?$/);       // Header: scheme[ something]
    if (!headerParts) {
        return callback(Err.badRequest('Invalid header syntax'));
    }

    var scheme = headerParts[1];
    if (scheme.toLowerCase() !== 'hawk') {
        return callback(Err.unauthorizedWithTs('', now, options.ntp));
    }

    var attributesString = headerParts[2];
    if (!attributesString) {
        return callback(Err.badRequest('Invalid header syntax'));
    }

    var attributes = {};
    var errorMessage = '';
    var verify = attributesString.replace(/(\w+)="([^"\\]*)"\s*(?:,\s*|$)/g, function ($0, $1, $2) {

        // Check valid attribute names

        if (['id', 'ts', 'nonce', 'ext', 'mac'].indexOf($1) === -1) {
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
        return callback(Err.badRequest(errorMessage || 'Bad header format'));
    }

    // Verify required header attributes

    if (!attributes.id ||
        !attributes.ts ||
        !attributes.nonce ||
        !attributes.mac) {

        return callback(Err.badRequest('Missing attributes'), null, attributes.ext);
    }
    
    // Check timestamp staleness
    
    if (Math.abs((attributes.ts * 1000) - now) > (options.timestampSkewSec * 1000)) {
        return callback(Err.unauthorizedWithTs('Stale timestamp', now, options.ntp), null, attributes.ext);
    }

    // Fetch Hawk credentials

    credentialsFunc(attributes.id, function (err, credentials) {

        if (err) {
            return callback(err, credentials || null, attributes.ext);
        }

        if (!credentials) {
            return callback(Err.unauthorized('Unknown credentials'), null, attributes.ext);
        }

        if (!credentials.key ||
            !credentials.algorithm) {

            return callback(Err.internal('Invalid credentials'), credentials, attributes.ext);
        }

        if (Crypto.algorithms.indexOf(credentials.algorithm) === -1) {
            return callback(Err.internal('Unknown algorithm'), credentials, attributes.ext);
        }

        // Calculate MAC

        var mac = Crypto.calculateMAC({
            header: 'core',
            key: credentials.key,
            algorithm: credentials.algorithm,
            timestamp: attributes.ts,
            nonce: attributes.nonce,
            method: req.method,
            uri: req.url,
            host: host.name,
            port: host.port,
            ext: attributes.ext
        });

        if (!Utils.fixedTimeComparison(mac, attributes.mac)) {
            return callback(Err.unauthorized('Bad mac'), credentials, attributes.ext);
        }

        // Check nonce

        options.nonceFunc(attributes.nonce, attributes.ts, function (err) {

            if (err) {
                return callback(Err.unauthorized('Invalid nonce'), credentials, attributes.ext);
            }

            // Successful authentication

            return callback(null, credentials, attributes.ext);
        });
    });
};


// Generate an Authorization header for a given request

/*
 * credentials is an object with the following keys: 'id, 'key', 'algorithm'.
 * options is an object with the following optional keys: 'ext', 'timestamp', 'nonce', 'localtimeOffsetMsec'
 */

exports.getAuthorizationHeader = function (credentials, method, uri, host, port, options) {

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

    var artifacts = {
        header: 'core',
        key: credentials.key,
        algorithm: credentials.algorithm,
        timestamp: options.timestamp || Math.floor(now / 1000),
        nonce: options.nonce || Utils.randomString(6),
        method: method,
        uri: uri,
        host: host,
        port: port,
        ext: options.ext
    };

    var mac = Crypto.calculateMAC(artifacts);

    if (!mac) {
        return '';
    }

    // Construct header

    var header = 'Hawk id="' + credentials.id + '", ts="' + artifacts.timestamp + '", nonce="' + artifacts.nonce + (options.ext ? '", ext="' + Utils.escapeHeaderAttribute(options.ext) : '') + '", mac="' + mac + '"';
    return header;
};


