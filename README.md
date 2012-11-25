![hawk Logo](https://raw.github.com/hueniverse/hawk/master/images/hawk.png)

**Hawk** is HTTP authentication scheme using a message authentication code (MAC) algorithm to provide partial HTTP request cryptographic verification.

Current version: **0.0.x**

[![Build Status](https://secure.travis-ci.org/hueniverse/hawk.png)](http://travis-ci.org/hueniverse/hawk)


# Table of Content

- [**Introduction**](#introduction)


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


