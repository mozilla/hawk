// Load modules

var Crypto = require('crypto');
var URL = require('url');
var Err = require('./error');
var Utils = require('./utils');


// Declare internals

var internals = {};


// Export utilities

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
 * timestampSkewSec     - number of seconds of permitted clock skew for incoming timestamps. Defaults to 60 seconds.
 *                        Provides a +/- skew which means actual allowed window is double the number of seconds.
 *
 * localtimeOffsetMsec  - local clock time offset express in a number of milliseconds (positive or negative).
 *                        Defaults to 0.
 *
 * ntp                  - hostname of the ntp server used to synchronize time between the client and the server. The
 *                        ntp server name is included when the client's timestamp is stale along with the server's
 *                        current timestamp. This allows browser-based clients to sync their application clock directly
 *                        with the server, while native clients can be smarter about managing time sync and caching
 *                        multiple clock offsets using the ntp server value provided. Defaults to 'pool.ntp.org'.
 */

exports.authenticate = function (req, credentialsFunc, options, callback) {

    // Default options

    options.hostHeaderName = (options.hostHeaderName ? options.hostHeaderName.toLowerCase() : 'host');
    options.nonceFunc = options.nonceFunc || function (nonce, ts, callback) { return callback(); };
    options.timestampSkewSec = options.timestampSkewSec || 60;                                              // 60 seconds
    options.localtimeOffsetMsec = options.localtimeOffsetMsec || 0;                                         // 0 milliseconds
    options.ntp = options.ntp || 'pool.ntp.org';

    // Application time
    
    var now = Date.now() + options.localtimeOffsetMsec;

    // Check required HTTP headers: host, authentication

    var hostHeader = req.headers[options.hostHeaderName];
    if (!hostHeader) {
        return callback(Err.badRequest('Missing Host header'), null, null);
    }

    if (!req.headers.authorization) {
        return callback(Err.unauthorizedWithTs('', now, options.ntp), null, null);
    }

    // Parse HTTP Authorization header

    var headerParts = req.headers.authorization.match(/^(\w+)(?:\s+(.*))?$/);       // Header: scheme[ something]
    if (!headerParts) {
        return callback(Err.badRequest('Invalid header syntax'), null, null);
    }

    var scheme = headerParts[1];
    if (scheme.toLowerCase() !== 'hawk') {
        return callback(Err.unauthorizedWithTs('', now, options.ntp), null, null);
    }

    var attributesString = headerParts[2];
    if (!attributesString) {
        return callback(Err.badRequest('Invalid header syntax'), null, null);
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
        return callback(Err.badRequest(errorMessage || 'Bad header format'), null, null);
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

    // Obtain host and port information

    var hostHeaderRegex = /^(?:(?:\r\n)?[\t ])*([^:]+)(?::(\d+))?(?:(?:\r\n)?[\t ])*$/; // Does not support IPv6
    var hostParts = hostHeader.match(hostHeaderRegex);

    if (!hostParts ||
        hostParts.length !== 3 ||
        !hostParts[1]) {

        return callback(Err.badRequest('Bad Host header'), null, attributes.ext);
    }

    var host = hostParts[1];
    var port = (hostParts[2] ? hostParts[2] : (req.connection && req.connection.encrypted ? 443 : 80));

    // Fetch Hawk credentials

    credentialsFunc(attributes.id, function (err, credentials) {

        if (err) {
            return callback(err, credentials || null, attributes.ext);
        }

        if (!credentials) {
            return callback(Err.unauthorized('Missing credentials'), null, attributes.ext);
        }

        if (!credentials.key ||
            !credentials.algorithm) {

            return callback(Err.internal('Invalid credentials'), credentials, attributes.ext);
        }

        if (['hmac-sha-1', 'hmac-sha-256'].indexOf(credentials.algorithm) === -1) {
            return callback(Err.internal('Unknown algorithm'), credentials, attributes.ext);
        }

        // Calculate MAC

        var mac = exports.calculateMAC(credentials.key, credentials.algorithm, attributes.ts, attributes.nonce, req.method, req.url, host, port, attributes.ext);
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


// Calculate the request MAC

exports.calculateMAC = function (key, algorithm, timestamp, nonce, method, uri, host, port, ext) {

    // Parse request URI

    var url = URL.parse(uri);

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


// Generate an Authorization header for a given request

/*
 * credentials is an object with the following keys: 'id, 'key', 'algorithm'.
 */

exports.getAuthorizationHeader = function (credentials, method, uri, host, port, ext, timestamp, nonce) {

    // Check request

    if (!credentials.id ||
        !credentials.key ||
        !credentials.algorithm) {

        // Invalid credential object
        return '';
    }

    // Calculate signature

    timestamp = timestamp || Math.floor(((new Date()).getTime() / 1000));
    nonce = nonce || Utils.randomString(6);
    var mac = exports.calculateMAC(credentials.key, credentials.algorithm, timestamp, nonce, method, uri, host, port, ext);

    if (!mac) {
        return '';
    }

    // Construct header

    var header = 'Hawk id="' + credentials.id + '", ts="' + timestamp + '", nonce="' + nonce + (ext ? '", ext="' + Utils.escapeHeaderAttribute (ext) : '') + '", mac="' + mac + '"';
    return header;
};


