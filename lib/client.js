'use strict';

// Load modules

const Url = require('url');

const B64 = require('b64');
const Boom = require('boom');
const Hoek = require('hoek');

const Cryptiles = require('cryptiles');
const Crypto = require('./crypto');
const Utils = require('./utils');


// Declare internals

const internals = {};


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
        timestamp: Date.now() / 1000,                       // A pre-calculated timestamp in seconds
        nonce: '2334f34f',                                  // A pre-generated nonce
        localtimeOffsetMsec: 400,                           // Time offset to sync with server time (ignored if timestamp provided)
        payload: '{"some":"payload"}',                      // UTF-8 encoded string for body hash generation (ignored if hash provided)
        contentType: 'application/json',                    // Payload content-type (ignored if hash provided)
        hash: 'U4MKKSmiVxk37JCCrAVIjV=',                    // Pre-calculated payload hash
        app: '24s23423f34dx',                               // Oz application id
        dlg: '234sz34tww3sd'                                // Oz delegated-by application id
    }
*/

exports.header = function (uri, method, options) {

    // Validate inputs

    if (!uri || (typeof uri !== 'string' && typeof uri !== 'object') ||
        !method || typeof method !== 'string' ||
        !options || typeof options !== 'object') {

        throw new Boom('Invalid argument type');
    }

    // Application time

    const timestamp = options.timestamp || Utils.nowSecs(options.localtimeOffsetMsec);

    // Validate credentials

    const credentials = options.credentials;
    if (!credentials ||
        !credentials.id ||
        !credentials.key ||
        !credentials.algorithm) {

        throw new Boom('Invalid credentials');
    }

    if (Crypto.algorithms.indexOf(credentials.algorithm) === -1) {
        throw new Boom('Unknown algorithm');
    }

    // Parse URI

    if (typeof uri === 'string') {
        uri = Url.parse(uri);
    }

    // Calculate signature

    const artifacts = {
        ts: timestamp,
        nonce: options.nonce || Cryptiles.randomString(6),
        method,
        resource: uri.pathname + (uri.search || ''),                            // Maintain trailing '?'
        host: uri.hostname,
        port: uri.port || (uri.protocol === 'http:' ? 80 : 443),
        hash: options.hash,
        ext: options.ext,
        app: options.app,
        dlg: options.dlg
    };

    // Calculate payload hash

    if (!artifacts.hash &&
        (options.payload || options.payload === '')) {

        artifacts.hash = Crypto.calculatePayloadHash(options.payload, credentials.algorithm, options.contentType);
    }

    const mac = Crypto.calculateMac('header', credentials, artifacts);

    // Construct header

    const hasExt = artifacts.ext !== null && artifacts.ext !== undefined && artifacts.ext !== '';       // Other falsey values allowed
    let header = 'Hawk id="' + credentials.id +
        '", ts="' + artifacts.ts +
        '", nonce="' + artifacts.nonce +
        (artifacts.hash ? '", hash="' + artifacts.hash : '') +
        (hasExt ? '", ext="' + Hoek.escapeHeaderAttribute(artifacts.ext) : '') +
        '", mac="' + mac + '"';

    if (artifacts.app) {
        header = header + ', app="' + artifacts.app +
            (artifacts.dlg ? '", dlg="' + artifacts.dlg : '') + '"';
    }

    return { header, artifacts };
};


// Validate server response

/*
    res:        node's response object
    artifacts:  object received from header().artifacts
    options: {
        payload:    optional payload received
        required:   specifies if a Server-Authorization header is required. Defaults to 'false'
    }
*/

exports.authenticate = function (res, credentials, artifacts, options) {

    options = options || {};

    artifacts = Hoek.clone(artifacts);

    const result = { headers: {} };

    if (res.headers['www-authenticate']) {

        // Parse HTTP WWW-Authenticate header

        try {
            var wwwAttributes = Utils.parseAuthorizationHeader(res.headers['www-authenticate'], ['ts', 'tsm', 'error']);
        }
        catch (err) {
            throw new Boom('Invalid WWW-Authenticate header');
        }

        result.headers['www-authenticate'] = wwwAttributes;

        // Validate server timestamp (not used to update clock since it is done via the SNPT client)

        if (wwwAttributes.ts) {
            const tsm = Crypto.calculateTsMac(wwwAttributes.ts, credentials);
            if (tsm !== wwwAttributes.tsm) {
                throw new Boom('Invalid server timestamp hash', { decorate: result });
            }
        }
    }

    // Parse HTTP Server-Authorization header

    if (!res.headers['server-authorization'] &&
        !options.required) {

        return result;
    }

    try {
        var serverAuthAttributes = Utils.parseAuthorizationHeader(res.headers['server-authorization'], ['mac', 'ext', 'hash']);
    }
    catch (err) {
        throw new Boom('Invalid Server-Authorization header', { decorate: result });
    }

    result.headers['server-authorization'] = serverAuthAttributes;

    artifacts.ext = serverAuthAttributes.ext;
    artifacts.hash = serverAuthAttributes.hash;

    const mac = Crypto.calculateMac('response', credentials, artifacts);
    if (mac !== serverAuthAttributes.mac) {
        throw new Boom('Bad response mac', { decorate: result });
    }

    if (!options.payload &&
        options.payload !== '') {

        return result;
    }

    if (!serverAuthAttributes.hash) {
        throw new Boom('Missing response hash attribute', { decorate: result });
    }

    const calculatedHash = Crypto.calculatePayloadHash(options.payload, credentials.algorithm, res.headers['content-type']);
    if (calculatedHash !== serverAuthAttributes.hash) {
        throw new Boom('Bad response payload mac', { decorate: result });
    }

    return result;
};


// Generate a bewit value for a given URI

/*
    uri: 'http://example.com/resource?a=b' or object from Url.parse()
    options: {

        // Required

        credentials: {
            id: 'dh37fgj492je',
            key: 'aoijedoaijsdlaksjdl',
            algorithm: 'sha256'                             // 'sha1', 'sha256'
        },
        ttlSec: 60 * 60,                                    // TTL in seconds

        // Optional

        ext: 'application-specific',                        // Application specific data sent via the ext attribute
        localtimeOffsetMsec: 400                            // Time offset to sync with server time
    };
*/

exports.getBewit = function (uri, options) {

    // Validate inputs

    if (!uri ||
        (typeof uri !== 'string' && typeof uri !== 'object') ||
        !options ||
        typeof options !== 'object' ||
        !options.ttlSec) {

        throw new Boom('Invalid inputs');
    }

    const ext = (options.ext === null || options.ext === undefined ? '' : options.ext);       // Zero is valid value

    // Application time

    const now = Utils.now(options.localtimeOffsetMsec);

    // Validate credentials

    const credentials = options.credentials;
    if (!credentials ||
        !credentials.id ||
        !credentials.key ||
        !credentials.algorithm) {

        throw new Boom('Invalid credentials');
    }

    if (Crypto.algorithms.indexOf(credentials.algorithm) === -1) {
        throw new Boom('Unknown algorithm');
    }

    // Parse URI

    if (typeof uri === 'string') {
        uri = Url.parse(uri);
    }

    // Calculate signature

    const exp = Math.floor(now / 1000) + options.ttlSec;
    const mac = Crypto.calculateMac('bewit', credentials, {
        ts: exp,
        nonce: '',
        method: 'GET',
        resource: uri.pathname + (uri.search || ''),                            // Maintain trailing '?'
        host: uri.hostname,
        port: uri.port || (uri.protocol === 'http:' ? 80 : 443),
        ext
    });

    // Construct bewit: id\exp\mac\ext

    const bewit = credentials.id + '\\' + exp + '\\' + mac + '\\' + ext;
    return B64.base64urlEncode(bewit);
};


// Generate an authorization string for a message

/*
    host: 'example.com',
    port: 8000,
    message: '{"some":"payload"}',                          // UTF-8 encoded string for body hash generation
    options: {

        // Required

        credentials: {
            id: 'dh37fgj492je',
            key: 'aoijedoaijsdlaksjdl',
            algorithm: 'sha256'                             // 'sha1', 'sha256'
        },

        // Optional

        timestamp: Date.now() / 1000,                       // A pre-calculated timestamp in seconds
        nonce: '2334f34f',                                  // A pre-generated nonce
        localtimeOffsetMsec: 400,                           // Time offset to sync with server time (ignored if timestamp provided)
    }
*/

exports.message = function (host, port, message, options) {

    options = options || {};

    // Validate inputs

    if (!host || typeof host !== 'string' ||
        !port || typeof port !== 'number' ||
        message === null || message === undefined || typeof message !== 'string' ||
        typeof options !== 'object') {

        throw new Boom('Invalid inputs');
    }

    // Application time

    const timestamp = options.timestamp || Utils.nowSecs(options.localtimeOffsetMsec);

    // Validate credentials

    const credentials = options.credentials;
    if (!credentials ||
        !credentials.id ||
        !credentials.key ||
        !credentials.algorithm) {

        throw new Boom('Invalid credentials');
    }

    if (Crypto.algorithms.indexOf(credentials.algorithm) === -1) {
        throw new Boom('Unknown algorithm');
    }

    // Calculate signature

    const artifacts = {
        ts: timestamp,
        nonce: options.nonce || Cryptiles.randomString(6),
        host,
        port,
        hash: Crypto.calculatePayloadHash(message, credentials.algorithm)
    };

    // Construct authorization

    const result = {
        id: credentials.id,
        ts: artifacts.ts,
        nonce: artifacts.nonce,
        hash: artifacts.hash,
        mac: Crypto.calculateMac('message', credentials, artifacts)
    };

    return result;
};



