var consolle = logger('RESOURCE'); 
var express = require('express');
var bodyParser = require('body-parser');
var cons = require('consolidate');
var nosql = require('nosql').load('database.nosql');
var __ = require('underscore');
var cors = require('cors');
var Q = require('q');
 
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

app.options('/resource', cors());
app.post('/resource', cors(), authorizeResource);

var server = app.listen(9002, 'localhost', function () {
  var host = server.address().address;
  var port = server.address().port;

  consolle.log('OAuth Resource Server is listening at http://%s:%s', host, port);
});

function authorizeResource (req, res) {
  consolle.log('Going to extract the token');
	var token = tokenFrom(req);
  consolle.log('...and the request token is... ' + token);

  promiseToCheck(token)
    .then(function(matchingToken) {
      consolle.log('Found matching token %s', matchingToken);
      res.json(resource);
    }, function(errorReason) {
      consolle.log('Token check failed: ' + errorReason);
      res.status(401).end();    
    });
};

function promiseToCheck(token) {
  var deferred = Q.defer();
  nosql.one(
    function(doc) { 
      return (doc.access_token === token) ? doc : null;
    },
    function(err, doc) {
      if (doc) {
        deferred.resolve(doc.access_token);
      } else {
        deferred.reject('no token found');
      }
    });
  return deferred.promise;
}

function tokenFrom(request) {
	var auth = request.headers['authorization'];

  if (auth && auth.toLowerCase().indexOf('bearer') === 0) {
    consolle.log('HTTP header');
    return auth.slice('bearer '.length);
  } else if (request.body && request.body.access_token) {
    consolle.log('POSTed form');
    return request.body.access_token;
  } else if (request.query && request.query.access_token) {
    consolle.log('GOTten querystring');
    return request.query.access_token;
  }
}

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