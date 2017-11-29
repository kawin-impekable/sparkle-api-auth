var OAuthServer = require('oauth2-server');
var Request = OAuthServer.Request;
var Response = OAuthServer.Response;

module.exports = function sparkleAuth(req, res, firestore) {
  var request = new Request(req);
  var response = new Response(res);
  var server = new OAuthServer({
    model: {
      getAccessToken: function (bearerToken) {
        return firestore.collection('oauth_tokens')
          .where('accessToken', '==', bearerToken)
          .get()
          .then(function(snapshot) {
            if (!snapshot.docs.length) return null;

            var firstMatch = snapshot.docs[0];
            var data = firstMatch.data();

            return {
              accessToken: data.accessToken,
              accessTokenExpiresAt: data.accessTokenExpiresAt,
              client: { id: data.clientId },
              user: { id: data.userId },
            };
          });
      }
    },
  });

  return server.authenticate(request, response)
    .catch(function(err) {
      throw err;
    })
};
