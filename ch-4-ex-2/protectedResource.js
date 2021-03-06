var consolle = logger('RESOURCE'); 
var express = require("express");
var bodyParser = require('body-parser');
var cons = require('consolidate');
var nosql = require('nosql').load('database.nosql');
var __ = require('underscore');
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
	var inToken = null;
	var auth = req.headers['authorization'];
	if (auth && auth.toLowerCase().indexOf('bearer') == 0) {
		inToken = auth.slice('bearer '.length);
	} else if (req.body && req.body.access_token) {
		inToken = req.body.access_token;
	} else if (req.query && req.query.access_token) {
		inToken = req.query.access_token
	}
	
	consolle.log('Incoming token: %s', inToken);
	nosql.one(function(token) {
		if (token.access_token == inToken) {
			return token;	
		}
	}, function(err, token) {
		if (token) {
			consolle.log("We found a matching token: %s", inToken);
		} else {
			consolle.log('No matching token was found.');
		}
		req.access_token = token; // horrible side effect!!
		next();
		return;
	});
};

var requireAccessToken = function(req, res, next) {
	if (req.access_token) {
		next(); // this is LAST.bind(undefined, req, res)
	} else {
		res.status(401).end(); // unauthorized
	}
};

var savedWords = [];

/* we'll have:
 * - getAccessToken(req, res, requireAccessToken);
 * - requireAccessToken(res, res, LAST.bind(undefined, res, req));
 */
app.get('/words', getAccessToken, requireAccessToken, function LAST(req, res) {
	/* Make this function require the "read" scope */
  var scopes = req.access_token.scope; // added by getAccessToken
  if (__(scopes).contains('read')) {
    consolle.log('Token can READ');
	  res.json({ words: savedWords.join(' '), timestamp: Date.now() });
  } else {
    consolle.log('Token canNOT read');
    res.set('WWW-Authenticate', 'Bearer realm=localhost:9002, error="insufficient scope", scope="read"');
    res.status(403).end();  // access denied
  }
});

app.post('/words', getAccessToken, requireAccessToken, function(req, res) {
	/* Make this function require the "write" scope */
  var scopes = req.access_token.scope; // added by getAccessToken
  if (__(scopes).contains('write')) {
    consolle.log('Token can WRITE');
    if (req.body.word) {
      savedWords.push(req.body.word);
    }
    res.status(201).end();  // created
  } else {
    consolle.log('Token canNOT write');
    res.set('WWW-Authenticate', 'Bearer realm=localhost:9002, error="insufficient scope", scope="write"');
    res.status(403).end();  // access denied
  }
});

app.delete('/words', getAccessToken, requireAccessToken, function(req, res) {
	/* Make this function require the "delete" scope */
  var scopes = req.access_token.scope; // added by getAccessToken
  if (__(scopes).contains('delete')) {
    consolle.log('Token can DELETE');
    savedWords.pop();
    res.status(204).end(); // no content
  } else {
    consolle.log('Token canNOT delete');
    res.set('WWW-Authenticate', 'Bearer realm=localhost:9002, error="insufficient scope", scope="delete"');
    res.status(403).end();  // access denied
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
      if (!p1) console.log(prefix + msg);
      else if (!p2) console.log(prefix + msg, p1);
      else console.log(prefix + msg, p1, p2);
    }
  }
};