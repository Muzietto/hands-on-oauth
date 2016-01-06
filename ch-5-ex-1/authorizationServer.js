var consolle = logger('SERVER'); 
var express = require("express");
var url = require("url");
var bodyParser = require('body-parser');
var randomstring = require("randomstring");
var cons = require('consolidate');
var nosql = require('nosql').load('database.nosql');
var querystring = require('querystring');
var qs = require("qs");
var __ = require('underscore');
__.string = require('underscore.string');
var base64url = require('base64url');
//var jose = require('./lib/jsrsasign.js');

var app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true })); // support form-encoded bodies (for the token endpoint)

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/authorizationServer');
app.set('json spaces', 4);

// authorization server information
var authServer = {
	authorizationEndpoint: 'http://localhost:9001/authorize',
	tokenEndpoint: 'http://localhost:9001/token'
};

// client information
var clients = [

  /*
   * Enter client information here
   */
	{
		"client_id": "oauth-client-1",
		"client_secret": "oauth-client-secret-1",
		"redirect_uris": ["http://localhost:9000/callback"],
		"scope": "foo"
	}
];

var codes = {};

var requests = {};

var getClient = function(clientId) {
	return __.find(clients, function(client) { return client.client_id == clientId; });
};

app.get('/', function(req, res) {
	res.render('index', {clients: clients, authServer: authServer});
});

app.get("/authorize", function(req, res){
  
  // http://stackoverflow.com/questions/14417592/node-js-difference-between-req-query-and-req-params/14508182#14508182
  consolle.log('Received req with field query=' + JSON.stringify(req.query));
	
	/* Process the request, validate the client, and send the user to the approval page */
  consolle.log('authorization request from client_id=' + req.query.client_id);
  var client = getClient(req.query.client_id);
	
  if (!client) {
    res.render('error', { error: 'client unknown for client_id=' + req.query.client_id });
    return;
  }
  
  if (!__(client.redirect_uris).contains(req.query.redirect_uri+'pippo')) {
    res.render('error', { error: 'invalid redirect uri for client_id=' + req.query.client_id });
    return;
  }
  

  

});

app.post('/approve', function(req, res) {

	/*
	 * Process the results of the approval page, authorize the client
	 */
	
	res.render('error', {error: 'Not implemented'});
	
});

app.post("/token", function(req, res){

	/*
	 * Process the request, issue an access token
	 */

	res.render('error', {error: 'Not implemented'});
	
});

app.use('/', express.static('files/authorizationServer'));

// clear the database
nosql.clear();

var server = app.listen(9001, 'localhost', function () {
  var host = server.address().address;
  var port = server.address().port;

  consolle.log('OAuth Authorization Server is listening at http://%s:%s', host, port);
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