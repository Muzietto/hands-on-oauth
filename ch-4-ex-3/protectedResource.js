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

app.get('/produce', getAccessToken, requireAccessToken, function(req, res) {
	var produce = { fruits: [], veggies: [], meats: [] };

	/* Add different kinds of produce based on the incoming token's scope */
  var scopes = req.access_token.scope; // added by getAccessToken
  if (__(scopes).contains('fruits')) {
    produce.fruits = ['apple', 'banana', 'kiwi'];
  }
  if (__(scopes).contains('veggies')) {
		produce.veggies = ['lettuce', 'onion', 'potato'];
  }
  if (__(scopes).contains('meats')) {
		produce.meats = ['bacon', 'steak', 'chicken breast'];
  }
  if (__(scopes).contains('low-carb')) {
		__(produce)
      .keys()
      .forEach(function(key) {
        consolle.log('filtering list ' + key);
        produce[key] = __(produce[key]).filter(function(item) {
          consolle.log('filtering ' + item);
          return !__(['banana', 'potato', 'bacon', 'steak']).contains(item);
        });
      });
  }
	res.json(produce);
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