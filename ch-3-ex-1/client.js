var consolle = {
  log: function(msg) { console.log('CLIENT -> ' + msg); }
};
 
var express = require('express');
var request = require('sync-request');
var url = require('url');
var qs = require('qs');
var querystring = require('querystring');
var cons = require('consolidate');
var randomstring = require('randomstring');

var app = express();

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/client');

// authorization server information
var authServer = {
	authorizationEndpoint: 'http://localhost:9001/authorize',
	tokenEndpoint: 'http://localhost:9001/token'
};

// client information
/*
 * Add the client information in here
 */
var client = {
  'client_id': 'oauth-client-1',
  'client_secret': 'oauth-client-secret-1',
  'redirect_uris': ['http://localhost:9000/callback'] // 9000 => client
}

var protectedResource = 'http://localhost:9002/resource';

var state = null;
var access_token = null;
var scope = null;

app.get('/', function (req, res) {
	res.render('index', {access_token: access_token, scope: scope});
});

var state;

app.get('/authorize', function(req, res){

  state = randomstring.generate();

	/*
	 * Send the user to the authorization server
	 */
  var authorizeUrl = url.parse(authServer.authorizationEndpoint, true);
  delete authorizeUrl.search;
  authorizeUrl.query.response_type = 'code';
  authorizeUrl.query.client_id = client.client_id;
  authorizeUrl.query.redirect_uri = client.redirect_uris[0];
  authorizeUrl.query.state = state;
	
  res.redirect(url.format(authorizeUrl));
});

app.get('/callback', function(req, res){

  consolle.log('state=' + state);
  consolle.log('req.query.state=' + req.query.state);
  
  if (req.query.state !== state) {
    var errMsg = 'State value didn\'t match!!!';
    res.render('error', { error: errMsg });
    consolle.log(errMsg);
    return;
  }

	/*
	 * Parse the response from the authorization server and get a token
	 */
	var code = req.query.code;
  var form_data = qs.stringify({
    grant_type: 'authorization_code',
    code: code,
    redirect_uri: client.redirect_uris[0]
  });

  var authorizationString = ''
    + querystring.escape(client.client_id)
    + ':'
    + querystring.escape(client.client_secret);

  consolle.log('as=' + authorizationString);
  
  var headers = {
    'content-type': 'application/x-www-form-urlencoded',
    'authorization': 'Basic ' + new Buffer(authorizationString).toString('base64')
  };

  var tokenResponse = request('POST', authServer.tokenEndpoint, {
    body: form_data,
    headers: headers
  });

  var body = JSON.parse(tokenResponse.getBody());

  access_token = body.access_token;

  res.render('index', {
    access_token: body.access_token,
    scope: scope
  });
});

app.get('/fetch_resource', function(req, res) {
  
	/*
	 * Use the access token to call the resource server
	 */
  if (!access_token) {
	  res.render('error', { error: 'Missing access token' });
  }
  
  var startTime = new Date().getTime();
  consolle.log('Requesting resource; token=' + access_token);
  var resource = request('POST', protectedResource, {
    headers: { 'authorization': 'Bearer ' + access_token } 
  });
  consolle.log('Response arrived after millis=' + (new Date().getTime() - startTime));
  
  if (resource.statusCode >= 200 && resource.statusCode < 300) {
    var body = JSON.parse(resource.getBody());
    res.render('data', { resource: body });
  } else {
    res.render('error', { error: 'Protected resource returned HTTP status code ' + resource.statusCode });
  }
});

app.use('/', express.static('files/client'));

var server = app.listen(9000, 'localhost', function () {
  var host = server.address().address;
  var port = server.address().port;
  consolle.log('OAuth Client is listening at http://%s:%s', host, port);
});
 
