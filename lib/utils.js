// Load modules

var Hoek = require('hoek');


// Declare internals

var internals = {
    randomSource: 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
};


// Import Hoek Utilities

internals.import = function () {

    for (var i in Hoek) {
        if (Hoek.hasOwnProperty(i)) {
            exports[i] = Hoek[i];
        }
    }
};

internals.import();


// Hawk version

exports.version = function () {

    return exports.loadPackage(__dirname + '/..').version;
};


// Generate a random string of given size (not for crypto)

exports.randomString = function (size) {

    var result = [];

    var len = internals.randomSource.length;
    for (var i = 0; i < size; ++i) {
        result.push(internals.randomSource[Math.floor(Math.random() * len)]);
    }

    return result.join('');
};


// Compare two strings using fixed time algorithm (to prevent time-based analysis of MAC digest match)

exports.fixedTimeComparison = function (a, b) {

    var mismatch = (a.length === b.length ? 0 : 1);
    if (mismatch) {
        b = a;
    }

    for (var i = 0, il = a.length; i < il; ++i) {
        var ac = a.charCodeAt(i);
        var bc = b.charCodeAt(i);
        mismatch += (ac === bc ? 0 : 1);
    }

    return (mismatch === 0);
};

