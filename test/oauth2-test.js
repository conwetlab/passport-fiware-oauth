const assert = require('assert');
const util = require('util');
const proxyquire = require('proxyquire')
const jwt = require('jsonwebtoken');

const CLIENT_ID = 'ABC123';
const CLIENT_SECRET = 'secret';


describe('FIWAREStrategy', () => {

    function strategy(fiwareStrategy, config) {
        if (config == null) {
            config = {
                clientID: CLIENT_ID,
                clientSecret: CLIENT_SECRET
            };
        }
        return new fiwareStrategy(config, function() {});
    };

    function requireStrategy(requestMock, config) {
        let FIWAREStrategy = proxyquire('../lib/passport-fiware-oauth/oauth2', {
            'request': requestMock
        });
        return strategy(FIWAREStrategy, config);
    }

    function requiredRawStrategy(config) {
        let FIWAREStrategy = require('../lib/passport-fiware-oauth/oauth2');
        return strategy(FIWAREStrategy, config);
    }

    it('should be named fiware', function () {
        let strategy = requiredRawStrategy();
        expect(strategy.name).toBe('fiware');
    });

    it('should set correct headers', function() {
        let strategy = requiredRawStrategy();
        let authHeaderValue = 'Basic ' + new Buffer(CLIENT_ID + ':' + CLIENT_SECRET).toString('base64');
        expect(strategy._oauth2._customHeaders['Authorization']).toBe(authHeaderValue);
    });

    describe('strategy when providing the IdM host', () => {
        let strategyH = requiredRawStrategy({
            clientID: CLIENT_ID,
            clientSecret: CLIENT_SECRET,
            serverURL: 'http://mycustomidm.com/'
        });

        it('should have changed the default host', function() {
            expect(strategyH.serverURL).toBe('http://mycustomidm.com');
        });
    });

    describe('strategy when loading user profile', () => {

        it('should load user profile without errors', function(done) {
            let strategyP = requireStrategy((params, callback) => {
                let body = {"organizations": [{ "id": "12", "name": "UPM", "roles": [{"id": "14", "name": "Admin"}] }],
                    "displayName": "Jared Hanson",
                    "app_id": "564",
                    "email": "example@fiware.org",
                    "id": "fiware-user-name",
                    "roles": [{"name": "provider", "id": "106"}]};

                callback(null, {}, JSON.stringify(body));
            });

            let callback = (err, profile) => {
                expect(err).toBeNull();
                expect(profile.provider).toBe('fiware');
                expect(profile.id).toBe('fiware-user-name');
                expect(profile.displayName).toBe('Jared Hanson');
                expect(profile.emails[0].value).toBe('example@fiware.org');
                expect(profile.appId).toBe('564');
                expect(profile.roles[0].name).toBe("provider");
                expect(profile.roles[0].id).toBe("106");
                expect(profile.organizations[0].id).toBe("12");
                expect(profile.organizations[0].name).toBe("UPM");
                expect(profile.organizations[0].roles[0].id).toBe("14");
                expect(profile.organizations[0].roles[0].name).toBe("Admin");

                expect(typeof(profile._raw)).toBe('string');
                expect(typeof(profile._json)).toBe('object');
                done();
            };
            strategyP.userProfile('access-token', callback);
        });

        it ('should load user profile from JWT', (done) => {
            const tokenContent = {
                "displayName": "Francisco",
                "roles": [
                    {
                        "id": "ddcb5f95-270f-46c5-8467-4c238d135ac8",
                        "name": "admin"
                    },
                    {
                        "id": "3832d309-08fb-403e-97ad-a93cf9f03df0",
                        "name": "seller"
                    }
                    ],
                "app_id": "19dd858c-328c-4642-93ab-da45e4d253ae",
                "trusted_apps": [],
                "isGravatarEnabled": false,
                "id": "e0d30f0e-64d4-4e80-9c39-a6b26da28acf",
                "authorization_decision": "",
                "app_azf_domain": "",
                "eidas_profile": {},
                "attributes": {},
                "shared_attributes": "",
                "username": "fdelavega",
                "email": "fdelavega@ficodes.com",
                "image": "",
                "gravatar": "",
                "extra": "",
                "type": "user",
                "iat": Date.now(),
                "exp": Date.now()
            }
            const secret = '281e126aa35c80f2';

            const token = jwt.sign(tokenContent, secret);

            let callback = (err, profile) => {
                expect(err).toBeNull();
                expect(profile.provider).toBe('fiware');
                expect(profile.id).toBe('e0d30f0e-64d4-4e80-9c39-a6b26da28acf');
                expect(profile.displayName).toBe('Francisco');
                expect(profile.emails[0].value).toBe('fdelavega@ficodes.com');
                expect(profile.appId).toBe('19dd858c-328c-4642-93ab-da45e4d253ae');
                expect(profile.roles[0].name).toBe("admin");
                expect(profile.roles[0].id).toBe("ddcb5f95-270f-46c5-8467-4c238d135ac8");
                expect(profile.roles[1].name).toBe("seller");
                expect(profile.roles[1].id).toBe("3832d309-08fb-403e-97ad-a93cf9f03df0");

                expect(typeof(profile._raw)).toBe('string');
                expect(typeof(profile._json)).toBe('object');
                done();
            };

            let strategy = requiredRawStrategy({
                clientID: CLIENT_ID,
                clientSecret: CLIENT_SECRET,
                key: secret
            });
            strategy.userProfile(token, callback);
        });
    });

    describe('strategy when loading user profile and encountering an error', () => {
        it('should load user profile without errors', function(done) {
            let strategyP = requireStrategy((params, callback) => {
                callback(new Error('something-went-wrong'));
            });

            let callback = (err, profile) => {
                expect(err).not.toBeNull();
                expect(err.constructor.name).toBe('InternalOAuthError');
                expect(profile).toBeUndefined();
                done();
            };
            strategyP.userProfile('access-token', callback);
        });
    });
});
