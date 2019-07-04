'use strict';

const Boom = require('@hapi/boom');
const Hoek = require('@hapi/hoek');

const Crypto = require('./crypto');
const Server = require('./server');


const internals = {};


exports.plugin = {
    pkg: require('../package.json'),
    requirements: {
        hapi: '>=17.7.0'
    },
    register: function (server) {

        server.auth.scheme('hawk', internals.hawk);
        server.auth.scheme('bewit', internals.bewit);
    }
};


internals.hawk = function (server, options) {

    Hoek.assert(options, 'Invalid hawk scheme options');
    Hoek.assert(options.getCredentialsFunc, 'Missing required getCredentialsFunc method in hawk scheme configuration');

    const settings = Hoek.clone(options);
    settings.hawk = settings.hawk || {};

    const scheme = {
        authenticate: async function (request, h) {

            try {
                var result = await Server.authenticate(request.raw.req, settings.getCredentialsFunc, settings.hawk);
            }
            catch (err) {
                const { credentials, artifacts } = err;
                return h.unauthenticated(err, credentials ? { credentials, artifacts } : undefined);
            }

            if (server.auth.lookup(request.route).payload) {
                request.events.once('peek', (chunk) => {

                    const payloadHash = Crypto.initializePayloadHash(request.auth.credentials.algorithm, request.headers['content-type']);
                    payloadHash.update(chunk);

                    request.events.on('peek', (chunk2) => payloadHash.update(chunk2));

                    request.events.once('finish', () => {

                        request.plugins['hapi-auth-hawk'] = { payloadHash: Crypto.finalizePayloadHash(payloadHash) };
                    });
                });
            }

            return h.authenticated(result);
        },
        payload: function (request, h) {

            if (!request.auth.artifacts.hash) {
                throw Boom.unauthorized(null, 'Hawk');      // Missing
            }

            const plugin = request.plugins['hapi-auth-hawk'];

            if (!plugin) {
                throw Boom.unauthorized('Payload is invalid');
            }

            try {
                Server.authenticatePayloadHash(plugin.payloadHash, request.auth.artifacts);
                return h.continue;
            }
            catch (err) {
                throw Boom.unauthorized('Payload is invalid');
            }
        },
        response: function (request, h) {

            const response = request.response;
            const payloadHash = Crypto.initializePayloadHash(request.auth.credentials.algorithm, response.headers['content-type']);

            response.header('trailer', 'server-authorization');
            response.header('transfer-encoding', 'chunked');

            delete response.headers['content-length'];  // Cannot not send a content-length header alongside transfer-encoding (https://tools.ietf.org/html/rfc7230#section-3.3.3)

            response.events.on('peek', (chunk) => {

                payloadHash.update(chunk);
            });

            response.events.once('finish', () => {

                const header = Server.header(request.auth.credentials, request.auth.artifacts, { hash: Crypto.finalizePayloadHash(payloadHash) });
                request.raw.res.addTrailers({ 'server-authorization': header });
            });

            return h.continue;
        }
    };

    return scheme;
};


internals.bewit = function (server, options) {

    Hoek.assert(options, 'Invalid bewit scheme options');
    Hoek.assert(options.getCredentialsFunc, 'Missing required getCredentialsFunc method in bewit scheme configuration');

    const settings = Hoek.clone(options);
    settings.hawk = settings.hawk || {};

    const scheme = {
        authenticate: async function (request, h) {

            try {
                const { credentials, attributes } = await Server.authenticateBewit(request.raw.req, settings.getCredentialsFunc, settings.hawk);
                return h.authenticated({ credentials, attributes });
            }
            catch (err) {
                const { credentials, attributes } = err;
                return h.unauthenticated(err, credentials ? { credentials, attributes } : undefined);
            }
        }
    };

    return scheme;
};
