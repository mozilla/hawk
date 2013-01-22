// Load modules

var Boom = require('boom');
var Sntp = require('sntp');


// Declare internals

var internals = {};


// Offset singleton

internals.offset = 0;
internals.updated = 0;


exports.offset = function (options, callback) {

    var now = Date.now();

    options.refresh = options.refresh || 60 * 60 * 1000;                // Hourly
    options.ntp = options.ntp || 'pool.ntp.org';

    if (internals.offset &&
        now - internals.updated < options.refresh) {

        return callback(null, internals.offset);
    }

    Sntp.time({ host: options.ntp }, function (err, time) {

        if (err) {
            return callback(Boom.internal(err.message));
        }

        internals.offset = time.t;
        internals.updated = now;

        return callback(null, time.t);
    });
};

