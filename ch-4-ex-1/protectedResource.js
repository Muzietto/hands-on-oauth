var consolle = logger('RESOURCE'); 
var express = require('express');
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
	'name': 'Protected Resource',
	'description': 'This data has been protected by OAuth 2.0'
};

var getAccessToken = function(req, res, next) {
	/*
	 * Scan for an access token on the incoming request.
	 */
  consolle.log('Going to extract the token');
	var inToken = null;
	var auth = req.headers['authorization'];

  if (auth && auth.toLowerCase().indexOf('bearer') === 0) {
    consolle.log('HTTP header');
    inToken = auth.slice('bearer '.length);
  } else if (req.body && req.body.access_token) {
    consolle.log('POSTed form');
    inToken = req.body.access_token;
  } else if (req.query && req.query.access_token) {
    consolle.log('GOTten querystring');
    inToken = req.query.access_token;
  }
  consolle.log('...and the token is... ' + inToken);

  nosql.one(function(token) {
    if (token.access_token === inToken) {
      return token;
    }
  }, function(err, token) {
    if (token) {
      consolle.log('Found matching token %s', inToken);
    } else {
      consolle.log('No matching token was found');
    }
    req.access_token = token;

    next();
    return;
  });
};

app.options('/resource', cors());
/*
 * Add the getAccessToken function to this handler
 */
app.post('/resource', cors(), getAccessToken, function(req, res){

	/*
	 * Check to see if the access token was found or not
	 */
  // stuck directly in the req by the helper method getAccessToken
  if (req.access_token) {
    // WRAP THIS LINE IN A CONDITIONAL STATEMENT
    res.json(resource);
    // WRAP THIS LINE IN A CONDITIONAL STATEMENT    
  } else {
    res.status(401).end();    
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