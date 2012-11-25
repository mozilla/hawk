![hawk Logo](https://raw.github.com/hueniverse/hawk/master/images/hawk.png)

**Hawk** is an HTTP authentication scheme using a message authentication code (MAC) algorithm to provide partial
HTTP request cryptographic verification. For more complex use cases such as access delegation, see [Oz](/hueniverse/oz).

Current version: **0.0.x**

[![Build Status](https://secure.travis-ci.org/hueniverse/hawk.png)](http://travis-ci.org/hueniverse/hawk)


# Table of Content

- [**Introduction**](#introduction)
  - [Usage Example](#usage-example)
  - [Protocol Example](#protocol-example)
<p></p>
- [**Security Considerations**](#security-considerations)
<p></p>
- [**Frequently Asked Questions**](#frequently-asked-questions)


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


# Security Considerations

The greatest sources of security risks are usually found not in **Hawk** but in the policies and procedures surrounding its use.
Implementers are strongly encouraged to assess how this module addresses their security requirements. This section includes
an incomplete list of security considerations that must be reviewed and understood before deploying **Hawk** on the server.

### MAC Keys Transmission

**Hawk** does not provide any mechanism for obtaining or transmitting the set of shared credentials required. Any mechanism used
to obtain **Hawk** credentials must ensure that these transmissions are protected using transport-layer mechanisms such as TLS.

### Confidentiality of Requests

While **Hawk** provides a mechanism for verifying the integrity of HTTP requests, it provides no guarantee of request
confidentiality. Unless other precautions are taken, eavesdroppers will have full access to the request content. Servers should
carefully consider the types of data likely to be sent as part of such requests, and employ transport-layer security mechanisms
to protect sensitive resources.

### Spoofing by Counterfeit Servers

**Hawk** makes no attempt to verify the authenticity of the server. A hostile party could take advantage of this by intercepting
the client's requests and returning misleading or otherwise incorrect responses. Service providers should consider such attacks
when developing services using this protocol, and should require transport-layer security for any requests where the authenticity
of the resource server or of server responses is an issue.

### Plaintext Storage of Credentials

The **Hawk** key functions the same way passwords do in traditional authentication systems. In order to compute the request MAC,
the server must have access to the key in plaintext form. This is in contrast, for example, to modern operating systems, which
store only a one-way hash of user credentials.

If an attacker were to gain access to these keys - or worse, to the server's database of all such keys - he or she would be able
to perform any action on behalf of any resource owner. Accordingly, it is critical that servers protect these keys from unauthorized
access.

### Entropy of Keys

Unless a transport-layer security protocol is used, eavesdroppers will have full access to authenticated requests and request
MAC values, and will thus be able to mount offline brute-force attacks to recover the key used. Servers should be careful to
assign keys which are long enough, and random enough, to resist such attacks for at least the length of time that the **Hawk**
credentials are valid.

For example, if the credentials are valid for two weeks, servers should ensure that it is not possible to mount a brute force
attack that recovers the key in less than two weeks. Of course, servers are urged to err on the side of caution, and use the
longest key reasonable.

It is equally important that the pseudo-random number generator (PRNG) used to generate these keys be of sufficiently high
quality. Many PRNG implementations generate number sequences that may appear to be random, but which nevertheless exhibit
patterns or other weaknesses which make cryptanalysis or brute force attacks easier. Implementers should be careful to use
cryptographically secure PRNGs to avoid these problems.

### Coverage Limitations

The request MAC only covers the HTTP `Host` header and does not cover any other headers which can often affect how the request
body is interpreted by the server (i.e. Content-Type). If the server behavior is influenced by the presence or value of such headers,
an attacker can manipulate the request header without being detected. Implementers should use the `ext` feature to pass
application-specific information via the Authorization header which is protected by the request MAC.


# Frequently Asked Questions

### Where is the protocol specification?

If you are looking for some prose explaining how all this works, there isn't any. **Hawk** is being developed as an open source
project instead of a standard. In other words, the [code](/hueniverse/hawk/tree/master/lib) is the specification.

### Does **Hawk** have anything to do with OAuth?

Short answer: no.

**Hawk** was originally proposed as the OAuth MAC Token specification. However, the OAuth working group in its consistent
incompetence failed to produce a final, usable solution to address one of the most popular use cases of OAuth 1.0 - using it
to authenticate simple client-server transactions (i.e. two-legged).

**Hawk** provides a simple HTTP authentication scheme for making client-server requests. It does not address the OAuth use case
of delegating access to a third party. If you are looking for an OAuth alternative, check out [Oz](/hueniverse/oz).

### Where can I find **Hawk** implementations in other languages?

At this time, **Hawk** is only implemented in JavaScript as a node.js module. Check this space for future support of other
languages (and such contributions are always welcome).

