var vows = require('vows');
var assert = require('assert');
var util = require('util');
var fiware = require('../lib/passport-fiware-oauth/index');


vows.describe('passport-fiware-oauth').addBatch({
  
  'module': {
    'should report a version': function (x) {
      assert.isString(fiware.version);
    },
    'should export OAuth 2.0 strategy': function (x) {
      assert.isFunction(fiware.OAuth2Strategy);
    },
  },
  
}).export(module);
