![hawk Logo](https://raw.github.com/hueniverse/hawk/master/images/hawk.png)

**Hawk** is HTTP authentication scheme using a message authentication code (MAC) algorithm to provide partial
HTTP request cryptographic verification. For more complex use cases such as access delegation, see [Oz](/hueniverse/oz).

Current version: **0.0.x**

[![Build Status](https://secure.travis-ci.org/hueniverse/hawk.png)](http://travis-ci.org/hueniverse/hawk)


# Table of Content

- [**Introduction**](#introduction)
  - [Protocol Example](#protocol-example)
  - [Usage Example](#usage-example)


# Introduction

**Hawk** is an HTTP authentication scheme providing a method for making authenticated HTTP requests with
partial cryptographic verification of the request, covering the HTTP method, request URI, and host.

Similar to the HTTP [Basic access authentication scheme](http://www.ietf.org/rfc/rfc2617.txt), the **Hawk**
scheme utilizes a set of client credentials which include an identifier and key. However, in contrast with
the Basic scheme, the key is never included in authenticated requests but is used to calculate a request MAC
value which is included instead.

The **Hawk** scheme requires the establishment of a shared symmetric key between the client and the server,
which is beyond the scope of this module. Typically, the shared credentials are established via an initial
TLS-protected phase or derived from some other shared confidential information available to both the client
and the server.

The primary design goals of this mechanism are to:
* simplify and improve HTTP authentication for services that are unwilling or unable to employ TLS for every request,
* secure the shared credentials against leakage when sent over a secure channel to the wrong server (e.g., when the client uses some form of dynamic configuration to determine where to send an authenticated request), and
* mitigate the exposure of credentials sent to a malicious server over an unauthenticated secure channel due to client failure to validate the server's identity as part of its TLS handshake.

Unlike the HTTP [Digest authentication scheme](http://www.ietf.org/rfc/rfc2617.txt), **Hawk** provides limited
protection against replay attacks which does not require prior interaction with the server. Instead, the client
provides a timestamp which the server can use to prevent replay attacks outside a narrow time window. Also unlike
Digest, this mechanism is not intended to protect the key itself (user's password in Digest) because the client
and server both have access to the key material in the clear.


## Protocol Example

The client attempts to access a protected resource without authentication, sending the following HTTP request to
the resource server:

```
GET /resource/1?b=1&a=2 HTTP/1.1
Host: 127.0.0.1:8000
```

The resource server returns the following authentication challenge:

```
HTTP/1.1 401 Unauthorized
WWW-Authenticate: Hawk
```

The client has previously obtained a set of **Hawk** credentials for accessing resources on the "http://example.com/"
server. The **Hawk** credentials issued to the client include the following attributes:

* Key identifier:  dh37fgj492je
* Key:  werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn
* Algorithm:  hmac-sha-256

The client generates the authentication header by calculating a timestamp (e.g. the number of seconds since January 1,
1970 00:00:00 GMT) and constructs the normalized request string (newline separated values):

```
1353832234
dh37fgj492je
GET
/resource/1?b=1&a=2
127.0.0.1
8000
some-app-data
```

The request MAC is calculated using the specified algorithm "hmac-sha-256" and the key over the normalized request string.
The result is base64-encoded to produce the request MAC:

```
/uYWR6W5vTbY3WKUAN6fa+7p1t+1Yl6hFxKeMLfR6kk=
```

The client includes the **Hawk** key identifier, timestamp, and request MAC with the request using the HTTP "Authorization"
request header field:

```
GET /resource/1?b=1&a=2 HTTP/1.1
Host: 127.0.0.1:8000
Authorization: Hawk id="dh37fgj492je", ts="1353832234", ext="some-app-data", mac="/uYWR6W5vTbY3WKUAN6fa+7p1t+1Yl6hFxKeMLfR6kk="
```

The server validates the request by calculating the request MAC again based on the request received and verifies the validity
and scope of the **Hawk** credentials. If valid, the server responds with the requested resource.


## Usage Example

Server code:

```javascript
var Http = require('http');
var Hawk = require('../lib/hawk');


// Credentials lookup function

var credentialsFunc = function (id, callback) {

    var credentials = {
        key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
        algorithm: 'hmac-sha-256',
        user: 'Steve'
    };

    return callback(null, credentials);
};

// Create HTTP server

var handler = function (req, res) {

    Hawk.authenticate(req, credentialsFunc, function (err, isAuthenticated, credentials, ext) {

        res.writeHead(isAuthenticated ? 200 : 401, { 'Content-Type': 'text/plain' });
        res.end(isAuthenticated ? 'Hello ' + credentials.user : 'Shoosh!');
    });
};

Http.createServer(handler).listen(8000, '127.0.0.1');
```

Client code:

```javascript
var Request = require('request');
var Hawk = require('../lib/hawk');


// Client credentials

var credentials = {
    id: 'dh37fgj492je',
    key: 'werxhqb98rpaxn39848xrunpaw3489ruxnpa98w4rxn',
    algorithm: 'hmac-sha-256'
}

// Send authenticated request

var options = {
    uri: 'http://127.0.0.1:8000/resource/1?b=1&a=2',
    method: 'GET',
    headers: {
        authorization: Hawk.getAuthorizationHeader(credentials, 'GET', '/resource/1?b=1&a=2', '127.0.0.1', 8000, 'some-app-data')
    }
};

Request(options, function (error, response, body) {

    console.log(response.statusCode + ': ' + body);
});
```
