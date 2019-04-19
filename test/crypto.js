'use strict';

const Code = require('@hapi/code');
const Hawk = require('..');
const Lab = require('@hapi/lab');


const internals = {};


const { describe, it } = exports.lab = Lab.script();
const expect = Code.expect;


describe('Crypto', () => {

    describe('generateNormalizedString()', () => {

        it('should return a valid normalized string', () => {

            expect(Hawk.crypto.generateNormalizedString('header', {
                ts: 1357747017,
                nonce: 'k3k4j5',
                method: 'GET',
                resource: '/resource/something',
                host: 'example.com',
                port: 8080
            })).to.equal('hawk.1.header\n1357747017\nk3k4j5\nGET\n/resource/something\nexample.com\n8080\n\n\n');
        });

        it('should return a valid normalized string (ext)', () => {

            expect(Hawk.crypto.generateNormalizedString('header', {
                ts: 1357747017,
                nonce: 'k3k4j5',
                method: 'GET',
                resource: '/resource/something',
                host: 'example.com',
                port: 8080,
                ext: 'this is some app data'
            })).to.equal('hawk.1.header\n1357747017\nk3k4j5\nGET\n/resource/something\nexample.com\n8080\n\nthis is some app data\n');
        });

        it('should return a valid normalized string (payload + ext)', () => {

            expect(Hawk.crypto.generateNormalizedString('header', {
                ts: 1357747017,
                nonce: 'k3k4j5',
                method: 'GET',
                resource: '/resource/something',
                host: 'example.com',
                port: 8080,
                hash: 'U4MKKSmiVxk37JCCrAVIjV/OhB3y+NdwoCr6RShbVkE=',
                ext: 'this is some app data'
            })).to.equal('hawk.1.header\n1357747017\nk3k4j5\nGET\n/resource/something\nexample.com\n8080\nU4MKKSmiVxk37JCCrAVIjV/OhB3y+NdwoCr6RShbVkE=\nthis is some app data\n');
        });
    });
});
