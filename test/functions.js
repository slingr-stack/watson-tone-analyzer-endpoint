/**
 * Created by lefunes on 20/09/16.
 */
"use strict"; // ECMAScript 5's strict mode

//Require the dev-dependencies
let chai = require('chai');
let chaiHttp = require('chai-http');
let should = chai.should();

chai.use(chaiHttp);

let endpoint = require('../endpoint');

const esToken = process.env._endpoints_services_token !== undefined ? process.env._endpoints_services_token : '';

const defaultHeaders = {
    "endpointsservicestoken": esToken
};

//Our parent block
describe('Base', () => {
    describe('Health - Alive', () => {
        it('it should be started', (done) => {
            chai.request(endpoint)
                .get('/api/system/alive')
                .end((err, res) => {
                    res.should.have.status(200);
                    res.body.should.be.a('object');
                    res.body.should.have.property('started');
                    res.body.started.should.eql(true);
                    done();
                });
        });
    });

    describe('Functions', () => {
        it('it should require token', (done) => {
            chai.request(endpoint)
                .post('/api/function')
                .send({})
                .end((err, res) => {
                    res.should.have.status(200);
                    res.body.should.be.a('object');

                    res.body.should.have.property('date');
                    res.body.date.should.be.a('number');

                    res.body.should.have.property('data');
                    res.body.data.should.be.a('object');

                    res.body.data.should.have.property('__endpoint_exception__');
                    res.body.data.__endpoint_exception__.should.to.be.true;

                    res.body.data.should.have.property('message');
                    res.body.data.message.should.eql('Invalid token');
                    
                    done();
                });
        });
        it('it should accept a valid token', (done) => {
            chai.request(endpoint)
                .post('/api/function')
                .set(defaultHeaders)
                .send({})
                .end((err, res) => {
                    res.should.have.status(200);
                    res.body.should.be.a('object');

                    res.body.should.have.property('date');
                    res.body.date.should.be.a('number');

                    res.body.should.have.property('data');
                    res.body.data.should.be.a('object');

                    res.body.data.should.have.property('__endpoint_exception__');
                    res.body.data.__endpoint_exception__.should.to.be.true;

                    res.body.data.should.have.property('message');
                    res.body.data.message.should.eql('Empty function name');

                    done();
                });
        });
    });
});

//Our parent block
/*
describe('Built-in functions', () => {
    describe('users', () => {
        it('it should GET all the users', (done) => {
            chai.request(endpoint)
                .post('/api/function')
                .set(defaultHeaders)
                .send({
                    function: 'users'
                })
                .end((err, res) => {
                    res.should.have.status(200);
                    res.body.should.be.a('object');

                    res.body.should.have.property('date');
                    res.body.date.should.be.a('number');

                    res.body.should.have.property('data');
                    res.body.data.should.be.a('object');

                    res.body.data.should.not.have.property('__endpoint_exception__');

                    res.body.data.should.have.property('ok');
                    res.body.data.ok.should.to.be.true;

                    res.body.data.should.have.property('members');
                    res.body.data.members.should.be.a('array');
                    res.body.data.members.length.should.to.be.not.empty;

                    done();
                });
        });
    });
});
*/

