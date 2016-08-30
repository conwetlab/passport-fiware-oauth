var vows = require('vows');
var assert = require('assert');
var util = require('util');
var FIWAREStrategy = require('../lib/passport-fiware-oauth/oauth2');

var CLIENT_ID = 'ABC123';
var CLIENT_SECRET = 'secret';


vows.describe('FIWAREStrategy').addBatch({
  
  'strategy': {
    topic: function() {
      return new FIWAREStrategy({
        clientID: CLIENT_ID,
        clientSecret: CLIENT_SECRET
      },
      function() {});
    },
    
    'should be named fiware': function (strategy) {
      assert.equal(strategy.name, 'fiware');
    },

    'should set correct headers': function(strategy) {
      var authHeaderValue = 'Basic ' + new Buffer(CLIENT_ID + ':' + CLIENT_SECRET).toString('base64');
      assert.equal(strategy._oauth2._customHeaders['Authorization'], authHeaderValue);
    }
  },

  'strategy when providing the IdM host': {
    topic: function() {
      return new FIWAREStrategy({
        clientID: CLIENT_ID,
        clientSecret: CLIENT_SECRET,
        serverURL: 'http://mycustomidm.com/'
      },
      function() {});
    },

    'should have changed the default host': function(strategy) {
      assert.equal(strategy.serverURL, 'http://mycustomidm.com');
    }
  },
  
  'strategy when loading user profile': {
    topic: function() {
      var strategy = new FIWAREStrategy({
        clientID: CLIENT_ID,
        clientSecret: CLIENT_SECRET
      },
      function() {});
      
      // mock
      strategy._oauth2.get = function(url, accessToken, callback) {
        var body = '{"organizations": [{ "id": "12", "name": "UPM", "roles": [{"id": "14", "name": "Admin"}] }], \
"displayName": "Jared Hanson", \
"app_id": "564", \
"email": "example@fiware.org", \
"id": "fiware-user-name", \
"roles": [{"name": "provider", "id": "106"}]}';
        
        callback(null, body, undefined);
      }
      
      return strategy;
    },
    
    'when told to load user profile': {
      topic: function(strategy) {
        var self = this;
        function done(err, profile) {
          self.callback(err, profile);
        }
        
        process.nextTick(function () {
          strategy.userProfile('access-token', done);
        });
      },
      
      'should not error' : function(err, req) {
        assert.isNull(err);
      },
      'should load profile' : function(err, profile) {
        assert.equal(profile.provider, 'fiware');
        assert.equal(profile.id, 'fiware-user-name');
        assert.equal(profile.displayName, 'Jared Hanson');
        assert.equal(profile.emails[0].value, 'example@fiware.org');
        assert.equal(profile.appId, '564');
        assert.equal(profile.roles[0].name, "provider");
        assert.equal(profile.roles[0].id, "106");
        assert.equal(profile.organizations[0].id, "12");
        assert.equal(profile.organizations[0].name, "UPM");
        assert.equal(profile.organizations[0].roles[0].id, "14");
        assert.equal(profile.organizations[0].roles[0].name, "Admin");
      },
      'should set raw property' : function(err, profile) {
        assert.isString(profile._raw);
      },
      'should set json property' : function(err, profile) {
        assert.isObject(profile._json);
      },
    },
  },
  
  'strategy when loading user profile and encountering an error': {
    topic: function() {
      var strategy = new FIWAREStrategy({
        clientID: CLIENT_ID,
        clientSecret: CLIENT_SECRET
      },
      function() {});
      
      // mock
      strategy._oauth2.get = function(url, accessToken, callback) {
        callback(new Error('something-went-wrong'));
      }
      
      return strategy;
    },
    
    'when told to load user profile': {
      topic: function(strategy) {
        var self = this;
        function done(err, profile) {
          self.callback(err, profile);
        }
        
        process.nextTick(function () {
          strategy.userProfile('access-token', done);
        });
      },
      
      'should error' : function(err, req) {
        assert.isNotNull(err);
      },
      'should wrap error in InternalOAuthError' : function(err, req) {
        assert.equal(err.constructor.name, 'InternalOAuthError');
      },
      'should not load profile' : function(err, profile) {
        assert.isUndefined(profile);
      },
    },
  },
  
}).export(module);
