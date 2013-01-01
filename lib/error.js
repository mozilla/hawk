// Load modules

var Http = require('http');
var NodeUtil = require('util');
var Utils = require('./utils');


// Declare internals

var internals = {};


exports = module.exports = internals.Error = function (code, message) {

    Utils.assert(this.constructor === internals.Error, 'Error must be instantiated using new');
    Utils.assert(code >= 400, 'Error code must be 4xx or 5xx');

    Error.call(this);

    this.code = code;
    this.message = message;
    this.headers = {};

    return this;
};

NodeUtil.inherits(internals.Error, Error);


internals.Error.prototype.toResponse = function () {

    // { code, payload, type, headers }

    var response = {
        code: this.code,
        payload: {
            error: Http.STATUS_CODES[this.code] || 'Unknown',
            code: this.code,
            message: this.message
        },
        headers: this.headers
    };

    return response;
};


// Utilities

internals.Error.badRequest = function (message) {

    return new internals.Error(400, message);
};


internals.Error.unauthorized = function (message) {

    return internals.Error.unauthorizedWithTs(message);
};


internals.Error.unauthorizedWithTs = function (message, now, ntp) {

    var err = new internals.Error(401, message);

    var attributes = '';
    if (now) {
        attributes += 'ts="' + now + '"';
    }

    if (ntp) {
        if (attributes) {
            attributes += ', ';
        }
        attributes += 'ntp="' + ntp + '"';
    }

    if (message) {
        if (attributes) {
            attributes += ', ';
        }
        attributes += 'error="' + Utils.escapeHeaderAttribute(message) + '"';
    }

    err.headers['WWW-Authenticate'] = 'Hawk' + (attributes ? ' ' + attributes : '');
    return err;
};


internals.Error.internal = function (message, data) {

    var err = new internals.Error(500, message);
    err.trace = Utils.displayStack(1);
    err.data = data;

    err.toResponse = function () {

        var response = {
            code: 500,
            payload: {
                error: Http.STATUS_CODES[500],
                code: 500,
                message: 'An internal server error occurred'                // Hide actual error from user
            }
        };

        return response;
    };

    return err;
};
