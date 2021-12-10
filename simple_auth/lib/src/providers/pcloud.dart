import 'dart:async';
import 'dart:convert';
import 'dart:math';

import "package:http/http.dart" as http;
import 'package:simple_auth/simple_auth.dart';

class PCloudApi extends OAuthApi {
  PCloudApi(String identifier, String clientId, String clientSecret, String redirectUrl,
      {List<String>? scopes, http.Client? client, Converter? converter, AuthStorage? authStorage, bool useEmbeddedBrowser = false})
      : super.fromIdAndSecret(identifier, clientId, clientSecret,
            client: client, scopes: scopes, converter: converter, authStorage: authStorage) {
    this.scopesRequired = false;
    this.tokenUrl = "https://api.pcloud.com/oauth2_token";
    this.baseUrl = "https://api.pcloud.com";
    this.authorizationUrl = "https://my.pcloud.com/oauth2/authorize";
    this.redirectUrl = redirectUrl;
    this.useEmbeddedBrowser = useEmbeddedBrowser;
  }

  Authenticator getAuthenticator() =>
      PCloudAuthenticator(identifier, clientId, clientSecret, tokenUrl, authorizationUrl, redirectUrl!, scopes, useEmbeddedBrowser);

  @override
  Future<OAuthAccount> getAccountFromAuthCode(WebAuthenticator authenticator) async {
    var auth = authenticator as PCloudAuthenticator;
    return OAuthAccount(identifier,
        created: DateTime.now().toUtc(),
        expiresIn: -1,
        scope: authenticator.scope,
        refreshToken: auth.token,
        tokenType: auth.tokenType,
        token: auth.token);
  }
}

class PCloudAuthenticator extends OAuthAuthenticator {
  late Uri redirectUri;
  late String state;

  PCloudAuthenticator(String? identifier, String? clientId, String? clientSecret, String? tokenUrl, String? baseUrl,
      String redirectUrl, List<String>? scopes, bool useEmbeddedBrowser)
      : super(identifier, clientId, clientSecret, tokenUrl, baseUrl, redirectUrl) {
    this.useEmbeddedBrowser = useEmbeddedBrowser;
    authCodeKey = "access_token";
    state = _createCryptoRandomString();
    redirectUri = Uri.parse(redirectUrl);
  }

  String? token;
  String? tokenType;
  String? uid;

  bool checkUrl(Uri url) {
    try {
      /*
       * If PCloud uses fragments instead of query parameters then swap convert
       * them to parameters so it is easier to parse. This also allows us to use
       * parameters if they don't use fragments.
       */
      if (url.hasFragment && !url.hasQuery) {
        url = url.replace(query: url.fragment);
      }

      if (!url.toString().contains(redirectUri.toString())) return false;
      if (url.query.isEmpty) return false;

      // verify state
      if (!url.queryParameters.containsKey('state') || url.queryParameters['state'] != state) return false;

      if (!url.queryParameters.containsKey(authCodeKey)) return false;
      var code = url.queryParameters[authCodeKey];
      if (code?.isEmpty ?? true) return false;
      token = code;
      tokenType = url.queryParameters["token_type"] == 'bearer' ? 'Bearer' : url.queryParameters["token_type"];
      uid = url.queryParameters["uid"];
      foundAuthCode(code);
      return true;
    } catch (exception) {
      print(exception);
      return false;
    }
  }

  @override
  Future<Map<String, dynamic>> getInitialUrlQueryParameters() async {
    var data = {
      "client_id": clientId,
      "response_type": "token",
      "redirect_uri": redirectUrl,
      "force_reapprove": "true",
    };

    if (state.isNotEmpty) {
      data["state"] = state;
    }
    return data;
  }

  String _createCryptoRandomString([int length = 32]) {
    final random = _getRandom();
    final values = List<int>.generate(length, (i) => random.nextInt(256));
    return base64Url.encode(values);
  }

  Random _getRandom() {
    try {
      return Random.secure();
    } catch (error, _) {
      return Random(DateTime.now().millisecondsSinceEpoch);
    }
  }
}
