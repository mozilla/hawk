// Load modules

var Http = require('http');
var Request = require('request');
var Hawk = require('../lib/hawk');


// Declare internals

var internals = {
    credentials: {
        dh37fgj492je: {
            id: 'dh37fgj492je',                                             // Required by Hawk.getAuthorizationHeader 
            key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
            algorithm: 'hmac-sha-256',
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

    Hawk.authenticate(req, credentialsFunc, function (err, isAuthenticated, credentials, ext) {

        res.writeHead(isAuthenticated ? 200 : 401, { 'Content-Type': 'text/plain' });
        res.end(isAuthenticated ? 'Hello ' + credentials.user : 'Shoosh!');
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
        authorization: Hawk.getAuthorizationHeader(internals.credentials.dh37fgj492je, 'GET', '/resource/1?b=1&a=2', '127.0.0.1', 8000, { ext: 'some-app-data' })
    }
};

console.log(options.headers.authorization);

Request(options, function (error, response, body) {

    console.log(response.statusCode + ': ' + body);
    process.exit(0);
});


