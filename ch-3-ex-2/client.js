var consolle = logger('CLIENT'); 
var express = require("express");
var request = require("sync-request");
var url = require("url");
var qs = require("qs");
var querystring = require('querystring');
var cons = require('consolidate');
var randomstring = require("randomstring");

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

var client = {
	"client_id": "oauth-client-1",
	"client_secret": "oauth-client-secret-1",
	"redirect_uris": ["http://localhost:9000/callback"],
	"scope": "foo"
};

var protectedResource = 'http://localhost:9002/resource';

var state = null;
var access_token = '987tghjkiu6trfghjuytrghj';
var scope = null;
var refresh_token = '98uhjrk2o3ij2r3oj32r23rmasd';

app.get('/', function (req, res) {
	res.render('index', {access_token: access_token, scope: scope, refresh_token: refresh_token});
});

app.get('/authorize', function(req, res){

	access_token = null;
	scope = null;
	state = randomstring.generate();
	
	var authorizeUrl = url.parse(authServer.authorizationEndpoint, true);
	delete authorizeUrl.search; // this is to get around odd behavior in the node URL library
	authorizeUrl.query.response_type = 'code';
	authorizeUrl.query.scope = client.scope;
	authorizeUrl.query.client_id = client.client_id;
	authorizeUrl.query.redirect_uri = client.redirect_uris[0];
	authorizeUrl.query.state = state;
	
	consolle.log("redirect", url.format(authorizeUrl));
	res.redirect(url.format(authorizeUrl));
});

app.get('/callback', function(req, res){
	
	if (req.query.error) {
		// it's an error response, act accordingly
		res.render('error', {error: req.query.error});
		return;
	}
	
	var resState = req.query.state;
	if (resState != state) {
		consolle.log('State DOES NOT MATCH: expected %s got %s', state, resState);
		res.render('error', {error: 'State value did not match'});
		return;
	}

	var code = req.query.code;

	var form_data = qs.stringify({
				grant_type: 'authorization_code',
				code: code,
				redirect_uri: client.redirect_uri
			});
	var headers = {
		'Content-Type': 'application/x-www-form-urlencoded',
		'Authorization': 'Basic ' + new Buffer(querystring.escape(client.client_id) + ':' + querystring.escape(client.client_secret)).toString('base64')
	};

	var tokRes = request('POST', authServer.tokenEndpoint, 
		{	
			body: form_data,
			headers: headers
		}
	);

	consolle.log('Requesting access token for code %s',code);
	
	if (tokRes.statusCode >= 200 && tokRes.statusCode < 300) {
    consolle.log('Token request returned ' + tokRes.getBody());
		var body = JSON.parse(tokRes.getBody());
	
		access_token = body.access_token;
		consolle.log('Got access token: %s', access_token);
		if (body.refresh_token) {
			refresh_token = body.refresh_token;
			consolle.log('Got refresh token: %s', refresh_token);
		}
		
		scope = body.scope;
		consolle.log('Got scope: %s', scope);

		res.render('index', {access_token: access_token, scope: scope, refresh_token: refresh_token});
	} else {
		res.render('error', {error: 'Unable to fetch access token, server response: ' + tokRes.statusCode})
	}
});

app.get('/fetch_resource', function(req, res) {

	consolle.log('Making request with access token %s', access_token);
	
	var headers = {
		'Authorization': 'Bearer ' + access_token,
		'Content-Type': 'application/x-www-form-urlencoded'
	};
	
	var resource = request('POST', protectedResource,
		{ headers: headers }
	);
	
	if (resource.statusCode >= 200 && resource.statusCode < 300) {
  	consolle.log('Request was granted');
		var body = JSON.parse(resource.getBody());
		res.render('data', { resource: body });
		return;
	} else {
  	consolle.log('Request was DENIED');
		access_token = null;
		
		/*
		 * Instead of returning an error, refresh the access token if we have a refresh token
		 */
    if (refresh_token) {
      consolle.log('Going to refresh the token at the server');
      refreshAccessToken(req, res);
      return;
    } else {
  		res.render('error', { error: 'token refresh failed with status code ' + resource.statusCode });
	  	return;
    }
	}
});

var refreshAccessToken = function(req, res) {

	/*
	 * Use the refresh token to get a new access token
	 */
  var form_data = qs.stringify({
    grant_type: 'refresh_token',
    refresh_token: refresh_token,
    client_id: client.client_id,
    client_secret: client.client_secret,
    redirect_uri: client.redirect_uris[0]
  });
	var headers = {
		'Content-Type': 'application/x-www-form-urlencoded'
	};
  var tokRes = request('POST', authServer.tokenEndpoint, {
    body: form_data,
    headers: headers
  });
  
  if (tokRes.statusCode >= 200 && tokRes.statusCode < 300) {
    consolle.log('Refresh attempt returned ' + tokRes.getBody());
    var body = JSON.parse(tokRes.getBody());
    access_token = body.access_token;
    
    if (body.refresh_token) {
      refresh_token = body.refresh_token;
    }
    
    scope = body.scope;
     
    res.redirect('/fetch_resource');
  } else {
    consolle.log('Refresh attempt failed');
    refresh_token = null;
    res.render('error', { error: 'Unable to refresh token' });
    return;  
  }
};

app.use('/', express.static('files/client'));

var server = app.listen(9000, 'localhost', function () {
  var host = server.address().address;
  var port = server.address().port;
  consolle.log('OAuth Client is listening at http://%s:%s', host, port);
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