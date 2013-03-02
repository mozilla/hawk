// Load modules

var Http = require('http');
var Request = require('request');
var Hawk = require('../lib');


// Declare internals

var internals = {
    credentials: {
        dh37fgj492je: {
            id: 'dh37fgj492je',                                             // Required by Hawk.getAuthorizationHeader 
            key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
            algorithm: 'sha256',
            user: 'Steve'
        }
    }
};


// Credentials lookup function

var credentialsFunc = function (id, callback) {

    return callback(null, internals.credentials[id]);
};


// Create HTTP server

var handler = function (req, res) {

    Hawk.authenticate(req, credentialsFunc, {}, function (err, credentials, attributes) {

        res.writeHead(!err ? 200 : 401, { 'Content-Type': 'text/plain' });
        res.end(!err ? 'Hello ' + credentials.user + ' ' + attributes.ext : 'Shoosh!');
    });
};

Http.createServer(handler).listen(8000, '127.0.0.1');


// Send unauthenticated request

Request('http://127.0.0.1:8000/resource/1?b=1&a=2', function (error, response, body) {

    console.log(response.statusCode + ': ' + body);
});


// Send authenticated request

var options = {
    uri: 'http://127.0.0.1:8000/resource/1?b=1&a=2',
    method: 'GET',
    headers: {
        authorization: Hawk.getAuthorizationHeader('http://127.0.0.1:8000/resource/1?b=1&a=2', 'GET', { credentials: internals.credentials.dh37fgj492je, ext: 'and welcome!' })
    }
};

console.log(options.headers.authorization);

Request(options, function (error, response, body) {

    console.log(response.statusCode + ': ' + body);
    process.exit(0);
});


