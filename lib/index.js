'use strict';


exports.sntp = require('@hapi/sntp');

exports.server = require('./server');

exports.client = require('./client');

exports.crypto = require('./crypto');

exports.utils = require('./utils');

exports.plugin = require('./plugin');

exports.uri = {
    authenticate: exports.server.authenticateBewit,
    getBewit: exports.client.getBewit
};
