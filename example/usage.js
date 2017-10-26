'use strict';

// Load modules

const Http = require('http');
const Request = require('request');
const Hawk = require('../lib');


// Declare internals

const internals = {
    credentials: {
        dh37fgj492je: {
            id: 'dh37fgj492je',                                             // Required by Hawk.client.header
            key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
            algorithm: 'sha256',
            user: 'Steve'
        }
    }
};


// Credentials lookup function

const credentialsFunc = function (id) {

    return internals.credentials[id];
};


// Create HTTP server

const handler = async function (req, res) {

    try {
        const { credentials, artifacts } = await Hawk.server.authenticate(req, credentialsFunc);

        const payload = 'Hello ' + credentials.user + ' ' + artifacts.ext;
        const headers = {
            'Content-Type': 'text/plain',
            'Server-Authorization': Hawk.server.header(credentials, artifacts, { payload, contentType: 'text/plain' })
        };

        res.writeHead(200, headers);
        res.end(payload);
    }
    catch (err) {
        const payload = 'Shoosh!';
        const headers = {
            'Content-Type': 'text/plain',
            'Server-Authorization': Hawk.server.header(err.credentials, err.artifacts, { payload, contentType: 'text/plain' })
        };

        res.writeHead(401, headers);
        res.end(payload);
    }
};

Http.createServer(handler).listen(8000, '127.0.0.1');


// Send unauthenticated request

Request('http://127.0.0.1:8000/resource/1?b=1&a=2', (err, response, body) => {

    if (err) {
        console.log(err);
    }

    console.log(response.statusCode + ': ' + body);
});


// Send authenticated request

const credentials = credentialsFunc('dh37fgj492je');
const header = Hawk.client.header('http://127.0.0.1:8000/resource/1?b=1&a=2', 'GET', { credentials, ext: 'and welcome!' });
const options = {
    uri: 'http://127.0.0.1:8000/resource/1?b=1&a=2',
    method: 'GET',
    headers: {
        authorization: header.header
    }
};

Request(options, (err, response, body) => {

    if (err) {
        process.exit(1);
    }

    const isValid = Hawk.client.authenticate(response, credentials, header.artifacts, { payload: body });
    console.log(response.statusCode + ': ' + body + (isValid ? ' (valid)' : ' (invalid)'));
    process.exit(0);
});
