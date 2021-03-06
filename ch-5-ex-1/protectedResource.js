var consolle = logger('RESOURCE'); 
var express = require("express");
var url = require("url");
var bodyParser = require('body-parser');
var randomstring = require("randomstring");
var cons = require('consolidate');
var nosql = require('nosql').load('database.nosql');
var qs = require("qs");
var querystring = require('querystring');
var request = require("sync-request");
var __ = require('underscore');
var base64url = require('base64url');
//var jose = require('./lib/jsrsasign.js');
var cors = require('cors');

var app = express();

app.use(bodyParser.urlencoded({ extended: true })); // support form-encoded bodies (for bearer tokens)

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/protectedResource');
app.set('json spaces', 4);

app.use('/', express.static('files/protectedResource'));
app.use(cors());

var resource = {
	"name": "Protected Resource",
	"description": "This data has been protected by OAuth 2.0"
};

var getAccessToken = function(req, res, next) {
	// check the auth header first
	var auth = req.headers['authorization'];
  consolle.log('Headers say ' + JSON.stringify(req.headers));
	var inToken = null;
	if (auth && auth.toLowerCase().indexOf('bearer') == 0) {
		inToken = auth.slice('bearer '.length);
    consolle.log('Bearer token in authorization header');
	} else if (req.body && req.body.access_token) {
		// not in the header, check in the form body
		inToken = req.body.access_token;
    consolle.log('Token in request body');
	} else if (req.query && req.query.access_token) {
		inToken = req.query.access_token
    consolle.log('Token in QS');
	}
	
	consolle.log('Incoming token: %s', inToken);
	nosql.one(function(token) {
    consolle.log('trying ' + JSON.stringify(token));
		if (token.access_token === inToken) {
      consolle.log('YEY!! - ' + token.access_token);
			return token;	
		}
	}, function(err, token) {
		if (token) {
			consolle.log("We found a matching token: %s", inToken);
		} else {
			consolle.log('No matching token was found.');
		}
		req.access_token = token;
		next();
		return;
	});
};

var requireAccessToken = function(req, res, next) {
	if (req.access_token) {
		next();
	} else {
		res.status(401).end();
	}
};

app.options('/resource', cors());

app.post("/resource", cors(), getAccessToken, function(req, res){

	if (req.access_token) {
    if (new Date().getTime() - req.access_token.timestamp < 3000) {
		  res.json(resource);
    } else {
		res.status(403).json({ error: 'token_expired' });      
    }
	} else {
		res.status(401).json({ error: 'unauthorized' });
	}
	
});

var server = app.listen(9002, 'localhost', function () {
  var host = server.address().address;
  var port = server.address().port;

  consolle.log('OAuth Resource Server is listening at http://%s:%s', host, port);
});

function logger(nodeName) {
  return {
    log: function(msg, p1, p2) {
      var prefix = nodeName + ' -> ';
      if (typeof p1 === 'undefined') console.log(prefix + msg);
      else if (typeof p2 === 'undefined') console.log(prefix + msg, p1);
      else console.log(prefix + msg, p1, p2);
    }
  }
};