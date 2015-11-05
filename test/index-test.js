var vows = require('vows');
var assert = require('assert');
var util = require('util');
var google = require('passport-fiware-oauth');


vows.describe('passport-fiware-oauth').addBatch({
  
  'module': {
    'should report a version': function (x) {
      assert.isString(google.version);
    },
    'should export OAuth 2.0 strategy': function (x) {
      assert.isFunction(google.OAuth2Strategy);
    },
  },
  
}).export(module);
