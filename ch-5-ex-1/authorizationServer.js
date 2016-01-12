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

// collection of all authorization requests received so far (and not yet redeemed)
var requests = {};

// collection of all authorization codes prepared so far (and not yet redeemed)
var codes = {};  // 'placeholders' to redeem the token afterwards

var getClient = function(clientId) {
	return __.find(clients, function(client) { return client.client_id == clientId; });
};

app.get('/', function(req, res) {
	res.render('index', { clients: clients, authServer: authServer });
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
  
  if (!__(client.redirect_uris).contains(req.query.redirect_uri)) {
    res.render('error', { error: 'invalid redirect uri for client_id=' + req.query.client_id });
    return;
  }
  
  // client is ok. let's save its generalities
  var reqid = randomstring.generate(8);
  requests[reqid] = req.query;

  // listify the scope string
  var rscope = req.query.scope ? req.query.scope.split(' ') : undefined;
  
  res.render('approve', { client: client, reqid: reqid, scope: rscope });
});

app.post('/approve', function(req, res) {

	/* Process the results of the approval page, authorize the client */
  consolle.log('got token request with body=' + JSON.stringify(req.body));
  
  var reqid = req.body.reqid;
  var query = requests[reqid];
  delete requests[reqid];
  
  if (!query) {
    consolle.log('No matching authorisation request for reqid=' + reqid);
    res.render('error', { error: 'No matching authorisation request for reqid=' + reqid });
    return;
  }

  // let's go to work
  var urlParsed = url.parse(query.redirect_uri);
  urlParsed.query = urlParsed.query || {};
  delete urlParsed.search; // just do it

  if (!req.body.approve) {  // namely req.body.deny
    consolle.log('No approval possible without explicit field approve');
    urlParsed.query.error = 'unsupported_response_type';
    consolle.log('redirecting... bye!')
    res.redirect(url.format(urlParsed));
    return;
  }

  var /*auth_*/code = randomstring.generate(8);
  codes[code] = { authorizationEndpointRequest: query };

  consolle.log('code sent to client is %s', code);
  urlParsed.query.code = code;
  consolle.log('state sent back to client is %s', query.state);
  urlParsed.query.state = query.state;
  consolle.log('redirecting... bye!')
  res.redirect(url.format(urlParsed));
  return;
}); // just 23 actual code lines out of the original 36!!

app.post("/token", function(req, res){
	/* Process the request, issue an access token */
  var clientId, clientSecret;
  
  consolle.log('METHOD 1) token request headers are ' + JSON.stringify(req.headers));
  var auth = req.headers['authorization'];
  consolle.log('authorization header is ' + auth);
  if (auth) {
    var clientCredentials = new Buffer(auth.slice('basic '.length), 'base64')
                                  .toString().split(':');
    clientId = querystring.unescape(clientCredentials[0]);
    consolle.log('clientId requesting token %s', clientId);
    clientSecret = querystring.unescape(clientCredentials[1]);
    consolle.log('clientSecret requesting token %s', clientSecret);
  }
  
  consolle.log('METHOD 2) token form body is ' + JSON.stringify(req.body));
  if (req.body.client_id) {
    consolle.log('form param is ' + req.body.client_id);  
    if (clientId) {
      consolle.log('Irregular attempt using two methods');  
      res.status(401).json({ error: 'invalid_client' });
      return; 
    }
    clientId = req.body.client_id;
    consolle.log('clientId requesting token %s', clientId);
    clientSecret = req.body.client_secret;
    consolle.log('clientSecret requesting token %s', clientSecret);
  }

  // whatever the method chosen, secrets must match
  var client = getClient(clientId);
  if (!client) {
    consolle.log('Unknown client!!');  
    res.status(401).json({ error: 'invalid_client' });    
    return; 
  }

  consolle.log('clientSecret requesting token %s', clientSecret);
  consolle.log('client secret stored was ' + client.client_secret);
  
  if (clientSecret !== client.client_secret) {
    consolle.log('Secrets do not match');  
    res.status(401).json({ error: 'invalid_client' });
    return; 
  }
  
  // client credentials seem ok. now we think at the actual token request:
  
  // verify grant type
  var grantType = req.body.grant_type;
  if (grantType !== 'authorization_code') {
    consolle.log('Unsupported grant type: ' + grantType);  
    res.status(400).json({ error: 'unsupported_grant_type' });
    return;    
  }

  // verify authentication code given previously to the client
  var code = codes[req.body.code];
  consolle.log('grant code is ' + req.body.code);  
  if (!code) {
    consolle.log('invalid grant code: ' + req.body.code);  
    res.status(400).json({ error: 'invalid_grant' });
    return;    
  }
  
  // invalidate authentication code no matter what
  delete codes[req.body.code];

  // compare authentication code with the clientId that requested it earlier
  if (code.authorizationEndpointRequest.client_id !== clientId) {
    consolle.log('invalid grant code: ' + req.body.code);  
    res.status(400).json({ error: 'invalid_grant' });
    return;    
  }
  
  // redeem the authentication code by creating a token and storing it
  var accessToken = randomstring.generate();
  nosql.insert({ access_token: accessToken, client_id: clientId });
  
  var tokenResponse = { access_token: accessToken, token_type: 'Bearer' }
  res.status(200).json(tokenResponse);
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
      if (typeof p1 === 'undefined') console.log(prefix + msg);
      else if (typeof p2 === 'undefined') console.log(prefix + msg, p1);
      else console.log(prefix + msg, p1, p2);
    }
  }
};