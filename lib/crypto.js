'use strict';

const Crypto = require('crypto');
const Url = require('url');

const Utils = require('./utils');


const internals = {};


// MAC normalization format version

exports.headerVersion = '1';                        // Prevent comparison of mac values generated with different normalized string formats


// Supported HMAC algorithms

exports.algorithms = ['sha1', 'sha256'];


// Generates the request MAC

/*
    type: 'header',                                 // 'header', 'bewit', 'response'
    credentials: {
        key: 'aoijedoaijsdlaksjdl',
        algorithm: 'sha256'                         // 'sha1', 'sha256'
    },
    options: {
        method: 'GET',
        resource: '/resource?a=1&b=2',
        host: 'example.com',
        port: 8080,
        ts: 1357718381034,
        nonce: 'd3d345f',
        hash: 'U4MKKSmiVxk37JCCrAVIjV/OhB3y+NdwoCr6RShbVkE=',
        ext: 'app-specific-data',
        app: 'hf48hd83qwkj',                        // Application id (Oz)
        dlg: 'd8djwekds9cj'                         // Delegated by application id (Oz), requires options.app
    }
*/

exports.generateRequestMac = function (type, credentials, options) {

    const normalized = exports.generateNormalizedString(type, options);

    const hmac = Crypto.createHmac(credentials.algorithm, credentials.key).update(normalized);
    const digest = hmac.digest('base64');
    return digest;
};


// Calculate the request MAC for verification

/*
    type: 'header',                                 // 'header', 'bewit', 'response'
    credentials: {
        key: 'aoijedoaijsdlaksjdl',
        algorithm: 'sha256'                         // 'sha1', 'sha256'
    },
    options: {
        method: 'GET',
        resource: '/resource?a=1&b=2',
        host: 'example.com',
        port: 8080,
        ts: 1357718381034,
        nonce: 'd3d345f',
        hash: 'U4MKKSmiVxk37JCCrAVIjV/OhB3y+NdwoCr6RShbVkE=',
        ext: 'app-specific-data',
        app: 'hf48hd83qwkj',                        // Application id (Oz)
        dlg: 'd8djwekds9cj'                         // Delegated by application id (Oz), requires options.app
    }
*/

exports.calculateServerMac = function (type, credentials, options, payload, contentType) {

    if (options.hash) {
        if (!payload) {
            console.log(`Security Warning: calculateServerMac was called trusting the client payload hash which provides no integrity checking and is insecure`);
        }
        else {
            // never trust client provided hash, always calculate server side
            options.hash = exports.calculatePayloadHash(payload, credentials.algorithm, contentType);
        }
    }

    const normalized = exports.generateNormalizedString(type, options);

    const hmac = Crypto.createHmac(credentials.algorithm, credentials.key).update(normalized);
    const digest = hmac.digest('base64');
    return digest;
};


exports.calculateMac = function (type, credentials, options) {

    console.log(`Deprecation Warning: calculateMac() is replaced by either calculateServerMac() or generateRequestMac()`);
    return exports.generateRequestMac(type, credentials, options);
};


exports.generateNormalizedString = function (type, options) {

    let resource = options.resource || '';
    if (resource &&
        resource[0] !== '/') {

        const url = Url.parse(resource, false);
        resource = url.path;                        // Includes query
    }

    let normalized = 'hawk.' + exports.headerVersion + '.' + type + '\n' +
                     options.ts + '\n' +
                     options.nonce + '\n' +
                     (options.method || '').toUpperCase() + '\n' +
                     resource + '\n' +
                     options.host.toLowerCase() + '\n' +
                     options.port + '\n' +
                     (options.hash || '') + '\n';

    if (options.ext) {
        normalized = normalized + options.ext.replace(/\\/g, '\\\\').replace(/\n/g, '\\n');
    }

    normalized = normalized + '\n';

    if (options.app) {
        normalized = normalized + options.app + '\n' +
                                  (options.dlg || '') + '\n';
    }

    return normalized;
};


exports.calculatePayloadHash = function (payload, algorithm, contentType) {

    const hash = exports.initializePayloadHash(algorithm, contentType);
    hash.update(payload || '');
    return exports.finalizePayloadHash(hash);
};


exports.initializePayloadHash = function (algorithm, contentType) {

    const hash = Crypto.createHash(algorithm);
    hash.update('hawk.' + exports.headerVersion + '.payload\n');
    hash.update(Utils.parseContentType(contentType) + '\n');
    return hash;
};


exports.finalizePayloadHash = function (hash) {

    hash.update('\n');
    return hash.digest('base64');
};


exports.calculateTsMac = function (ts, credentials) {

    const hmac = Crypto.createHmac(credentials.algorithm, credentials.key);
    hmac.update('hawk.' + exports.headerVersion + '.ts\n' + ts + '\n');
    return hmac.digest('base64');
};


exports.timestampMessage = function (credentials, localtimeOffsetMsec) {

    const now = Utils.nowSecs(localtimeOffsetMsec);
    const tsm = exports.calculateTsMac(now, credentials);
    return { ts: now, tsm };
};
