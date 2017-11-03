'use strict';

// Load modules

const Boom = require('boom');
const Cryptiles = require('cryptiles');
const Hoek = require('hoek');

const Crypto = require('./crypto');
const Utils = require('./utils');


// Declare internals

const internals = {};


// Hawk authentication

/*
   req:                 node's HTTP request object or an object as follows:

                        const request = {
                            method: 'GET',
                            url: '/resource/4?a=1&b=2',
                            host: 'example.com',
                            port: 8080,
                            authorization: 'Hawk id="dh37fgj492je", ts="1353832234", nonce="j4h3g2", ext="some-app-ext-data", mac="6R4rV5iE+NPoym+WwjeHzjAGXUtLNIxmo1vpMofpLAE="'
                        };

   credentialsFunc:     required function to lookup the set of Hawk credentials based on the provided credentials id.
                        The credentials include the MAC key, MAC algorithm, and other attributes (such as username)
                        needed by the application. This function is the equivalent of verifying the username and
                        password in Basic authentication.

                        const credentialsFunc = async function (id) {

                            // Lookup credentials in database

                            const item = await db.lookup(id);       // Can throw errors
                            if (!item) {
                                return null;
                            }

                            const credentials = {
                                // Required
                                key: item.key,
                                algorithm: item.algorithm,
                                // Application specific
                                user: item.user
                            };

                            return credentials;
                        };

   options: {

        hostHeaderName:        optional header field name, used to override the default 'Host' header when used
                               behind a cache of a proxy. Apache2 changes the value of the 'Host' header while preserving
                               the original (which is what the module must verify) in the 'x-forwarded-host' header field.
                               Only used when passed a node Http.ServerRequest object.

        nonceFunc:             optional nonce validation function. The function signature is `async function(key, nonce, ts)`
                               and it must return no value for success or throw an error for invalid state.

        timestampSkewSec:      optional number of seconds of permitted clock skew for incoming timestamps. Defaults to 60 seconds.
                               Provides a +/- skew which means actual allowed window is double the number of seconds.

        localtimeOffsetMsec:   optional local clock time offset express in a number of milliseconds (positive or negative).
                               Defaults to 0.

        payload:               optional payload for validation. The client calculates the hash value and includes it via the 'hash'
                               header attribute. The server always ensures the value provided has been included in the request
                               MAC. When this option is provided, it validates the hash value itself. Validation is done by calculating
                               a hash value over the entire payload (assuming it has already be normalized to the same format and
                               encoding used by the client to calculate the hash on request). If the payload is not available at the time
                               of authentication, the authenticatePayload() method can be used by passing it the credentials and
                               attributes.hash returned from authenticate().

        host:                  optional host name override. Only used when passed a node request object.
        port:                  optional port override. Only used when passed a node request object.
    }

    Return value: { credentials, artifacts } or throws an error.
 */

exports.authenticate = async function (req, credentialsFunc, options) {

    options = options || {};

    // Default options

    options.timestampSkewSec = options.timestampSkewSec || 60;                                                  // 60 seconds

    // Application time

    const now = Utils.now(options.localtimeOffsetMsec);                           // Measure now before any other processing

    // Convert node Http request object to a request configuration object

    const request = Utils.parseRequest(req, options);

    // Parse HTTP Authorization header

    const attributes = Utils.parseAuthorizationHeader(request.authorization);

    // Construct artifacts container

    const artifacts = {
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

        throw Boom.badRequest('Missing attributes', { decorate: { artifacts } });
    }

    // Fetch Hawk credentials

    try {
        var credentials = await credentialsFunc(attributes.id);
    }
    catch (err) {
        throw Boom.boomify(err, { decorate: { artifacts } });
    }

    if (!credentials) {
        throw Object.assign(Utils.unauthorized('Unknown credentials'), { artifacts });
    }

    const result = { credentials, artifacts };

    if (!credentials.key ||
        !credentials.algorithm) {

        throw new Boom('Invalid credentials', { decorate: result });
    }

    if (Crypto.algorithms.indexOf(credentials.algorithm) === -1) {
        throw new Boom('Unknown algorithm', { decorate: result });
    }

    // Calculate MAC

    const mac = Crypto.calculateMac('header', credentials, artifacts);
    if (!Cryptiles.fixedTimeComparison(mac, attributes.mac)) {
        throw Object.assign(Utils.unauthorized('Bad mac'), result);
    }

    // Check payload hash

    if (options.payload ||
        options.payload === '') {

        if (!attributes.hash) {
            throw Object.assign(Utils.unauthorized('Missing required payload hash'), result);
        }

        const hash = Crypto.calculatePayloadHash(options.payload, credentials.algorithm, request.contentType);
        if (!Cryptiles.fixedTimeComparison(hash, attributes.hash)) {
            throw Object.assign(Utils.unauthorized('Bad payload hash'), result);
        }
    }

    // Check nonce

    if (options.nonceFunc) {
        try {
            await options.nonceFunc(credentials.key, attributes.nonce, attributes.ts);
        }
        catch (err) {
            throw Object.assign(Utils.unauthorized('Invalid nonce'), result);
        }
    }

    // Check timestamp staleness

    if (Math.abs((attributes.ts * 1000) - now) > (options.timestampSkewSec * 1000)) {
        const tsm = Crypto.timestampMessage(credentials, options.localtimeOffsetMsec);
        throw Object.assign(Utils.unauthorized('Stale timestamp', tsm), result);
    }

    // Successful authentication

    return result;
};


// Authenticate payload hash - used when payload cannot be provided during authenticate()

/*
    payload:        raw request payload
    credentials:    from authenticate()
    artifacts:      from authenticate()
    contentType:    req.headers['content-type']

    Return value: { credentials, artifacts } or throws an error.
*/

exports.authenticatePayload = function (payload, credentials, artifacts, contentType) {

    const calculatedHash = Crypto.calculatePayloadHash(payload, credentials.algorithm, contentType);
    if (!Cryptiles.fixedTimeComparison(calculatedHash, artifacts.hash)) {
        throw Object.assign(Utils.unauthorized('Bad payload hash'), { credentials, artifacts });
    }
};


// Authenticate payload hash - used when payload cannot be provided during authenticate()

/*
    calculatedHash: the payload hash calculated using Crypto.calculatePayloadHash()
    artifacts:      from authenticate()

    Return value: { artifacts } or throws an error.
*/

exports.authenticatePayloadHash = function (calculatedHash, artifacts) {

    if (!Cryptiles.fixedTimeComparison(calculatedHash, artifacts.hash)) {
        throw Object.assign(Utils.unauthorized('Bad payload hash'), { artifacts });
    }
};


// Generate a Server-Authorization header for a given response

/*
    credentials: {},                                        // Object received from authenticate()
    artifacts: {}                                           // Object received from authenticate(); 'mac', 'hash', and 'ext' - ignored
    options: {
        ext: 'application-specific',                        // Application specific data sent via the ext attribute
        payload: '{"some":"payload"}',                      // UTF-8 encoded string for body hash generation (ignored if hash provided)
        contentType: 'application/json',                    // Payload content-type (ignored if hash provided)
        hash: 'U4MKKSmiVxk37JCCrAVIjV='                     // Pre-calculated payload hash
    }
*/

exports.header = function (credentials, artifacts, options) {

    options = options || {};

    // Prepare inputs

    if (!artifacts ||
        typeof artifacts !== 'object' ||
        typeof options !== 'object') {

        throw new Boom('Invalid inputs');
    }

    artifacts = Hoek.clone(artifacts);
    delete artifacts.mac;
    artifacts.hash = options.hash;
    artifacts.ext = options.ext;

    // Validate credentials

    if (!credentials ||
        !credentials.key ||
        !credentials.algorithm) {

        throw new Boom('Invalid credentials');
    }

    if (Crypto.algorithms.indexOf(credentials.algorithm) === -1) {
        throw new Boom('Unknown algorithm');
    }

    // Calculate payload hash

    if (!artifacts.hash &&
        (options.payload || options.payload === '')) {

        artifacts.hash = Crypto.calculatePayloadHash(options.payload, credentials.algorithm, options.contentType);
    }

    const mac = Crypto.calculateMac('response', credentials, artifacts);

    // Construct header

    let header = 'Hawk mac="' + mac + '"' +
        (artifacts.hash ? ', hash="' + artifacts.hash + '"' : '');

    if (artifacts.ext !== null &&
        artifacts.ext !== undefined &&
        artifacts.ext !== '') {                       // Other falsey values allowed

        header = header + ', ext="' + Hoek.escapeHeaderAttribute(artifacts.ext) + '"';
    }

    return header;
};


/*
 * Arguments and options are the same as authenticate() with the exception that the only supported options are:
 * 'hostHeaderName', 'localtimeOffsetMsec', 'host', 'port'
 */


//                       1     2             3           4
internals.bewitRegex = /^(\/.*)([\?&])bewit\=([^&$]*)(?:&(.+))?$/;


exports.authenticateBewit = async function (req, credentialsFunc, options) {

    options = options || {};

    // Application time

    const now = Utils.now(options.localtimeOffsetMsec);

    // Convert node Http request object to a request configuration object

    const request = Utils.parseRequest(req, options);

    // Extract bewit

    if (request.url.length > Utils.limits.maxMatchLength) {
        throw Boom.badRequest('Resource path exceeds max length');
    }

    const resource = request.url.match(internals.bewitRegex);
    if (!resource) {
        throw Utils.unauthorized();
    }

    // Bewit not empty

    if (!resource[3]) {
        throw Utils.unauthorized('Empty bewit');
    }

    // Verify method is GET

    if (request.method !== 'GET' &&
        request.method !== 'HEAD') {

        throw Utils.unauthorized('Invalid method');
    }

    // No other authentication

    if (request.authorization) {
        throw Boom.badRequest('Multiple authentications');
    }

    // Parse bewit

    try {
        var bewitString = Hoek.base64urlDecode(resource[3]);
    }
    catch (err) {
        throw Boom.badRequest('Invalid bewit encoding');
    }

    // Bewit format: id\exp\mac\ext ('\' is used because it is a reserved header attribute character)

    const bewitParts = bewitString.split('\\');
    if (bewitParts.length !== 4) {
        throw Boom.badRequest('Invalid bewit structure');
    }

    const bewit = {
        id: bewitParts[0],
        exp: parseInt(bewitParts[1], 10),
        mac: bewitParts[2],
        ext: bewitParts[3] || ''
    };

    if (!bewit.id ||
        !bewit.exp ||
        !bewit.mac) {

        throw Boom.badRequest('Missing bewit attributes');
    }

    // Construct URL without bewit

    let url = resource[1];
    if (resource[4]) {
        url = url + resource[2] + resource[4];
    }

    // Check expiration

    if (bewit.exp * 1000 <= now) {
        throw Object.assign(Utils.unauthorized('Access expired'), { bewit });
    }

    // Fetch Hawk credentials

    try {
        var credentials = await credentialsFunc(bewit.id);
    }
    catch (err) {
        throw new Boom(err, { decorate: { bewit } });
    }

    if (!credentials) {
        throw Object.assign(Utils.unauthorized('Unknown credentials'), { bewit });
    }

    const result = { credentials, attributes: bewit };

    if (!credentials.key ||
        !credentials.algorithm) {

        throw new Boom('Invalid credentials', { decorate: result });
    }

    if (Crypto.algorithms.indexOf(credentials.algorithm) === -1) {
        throw new Boom('Unknown algorithm', { decorate: result });
    }

    // Calculate MAC

    const mac = Crypto.calculateMac('bewit', credentials, {
        ts: bewit.exp,
        nonce: '',
        method: 'GET',
        resource: url,
        host: request.host,
        port: request.port,
        ext: bewit.ext
    });

    if (!Cryptiles.fixedTimeComparison(mac, bewit.mac)) {
        throw Object.assign(Utils.unauthorized('Bad mac'), result);
    }

    // Successful authentication

    return result;
};


/*
 *  options are the same as authenticate() with the exception that the only supported options are:
 * 'nonceFunc', 'timestampSkewSec', 'localtimeOffsetMsec'
 */

exports.authenticateMessage = async function (host, port, message, authorization, credentialsFunc, options) {

    options = options || {};

    // Default options

    options.timestampSkewSec = options.timestampSkewSec || 60;                                                  // 60 seconds

    // Application time

    const now = Utils.now(options.localtimeOffsetMsec);                       // Measure now before any other processing

    // Validate authorization

    if (!authorization.id ||
        !authorization.ts ||
        !authorization.nonce ||
        !authorization.hash ||
        !authorization.mac) {

        throw Boom.badRequest('Invalid authorization');
    }

    // Fetch Hawk credentials

    const credentials = await credentialsFunc(authorization.id);
    if (!credentials) {
        throw Utils.unauthorized('Unknown credentials');
    }

    const result = { credentials };

    if (!credentials.key ||
        !credentials.algorithm) {

        throw new Boom('Invalid credentials', { decorate: result });
    }

    if (Crypto.algorithms.indexOf(credentials.algorithm) === -1) {
        throw new Boom('Unknown algorithm', { decorate: result });
    }

    // Construct artifacts container

    const artifacts = {
        ts: authorization.ts,
        nonce: authorization.nonce,
        host,
        port,
        hash: authorization.hash
    };

    // Calculate MAC

    const mac = Crypto.calculateMac('message', credentials, artifacts);
    if (!Cryptiles.fixedTimeComparison(mac, authorization.mac)) {
        throw Object.assign(Utils.unauthorized('Bad mac'), result);
    }

    // Check payload hash

    const hash = Crypto.calculatePayloadHash(message, credentials.algorithm);
    if (!Cryptiles.fixedTimeComparison(hash, authorization.hash)) {
        throw Object.assign(Utils.unauthorized('Bad message hash'), result);
    }

    // Check nonce

    if (options.nonceFunc) {
        try {
            await options.nonceFunc(credentials.key, authorization.nonce, authorization.ts);
        }
        catch (err) {
            throw Object.assign(Utils.unauthorized('Invalid nonce'), result);
        }
    }

    // Check timestamp staleness

    if (Math.abs((authorization.ts * 1000) - now) > (options.timestampSkewSec * 1000)) {
        throw Object.assign(Utils.unauthorized('Stale timestamp'), result);
    }

    // Successful authentication

    return result;
};
