import 'dart:async';
import 'dart:convert';
import 'dart:math';

import "package:http/http.dart" as http;
import 'package:simple_auth/simple_auth.dart';

class BoxApiV1 extends OAuthApi {

  BoxApiV1(String identifier, String clientId, String clientSecret, String redirectUrl,
      {List<String>? scopes,
        http.Client? client,
        Converter? converter,
        AuthStorage? authStorage,
        bool useEmbeddedBrowser = false})
      : super.fromIdAndSecret(identifier, clientId, clientSecret,
      client: client, scopes: scopes, converter: converter, authStorage: authStorage) {
    this.scopesRequired = false;
    this.tokenUrl = 'https://api.box.com/oauth2/token';
    this.baseUrl = 'https://account.box.com';
    this.authorizationUrl = 'https://account.box.com/api/oauth2/authorize';
    this.redirectUrl = redirectUrl;
    this.useEmbeddedBrowser = useEmbeddedBrowser;
  }

  @override
  Authenticator getAuthenticator() =>
      BoxV1Authenticator(
          identifier,
          clientId,
          clientSecret,
          tokenUrl,
          authorizationUrl,
          redirectUrl!,
          scopes,
          useEmbeddedBrowser);
}

class BoxV1Authenticator extends OAuthAuthenticator {
  late Uri redirectUri;
  late String state;

  BoxV1Authenticator(String? identifier, String? clientId, String? clientSecret, String? tokenUrl, String? baseUrl,
      String redirectUrl, List<String>? scopes, bool useEmbeddedBrowser)
      : super(identifier, clientId, clientSecret, tokenUrl, baseUrl, redirectUrl) {
    this.useEmbeddedBrowser = useEmbeddedBrowser;
    redirectUri = Uri.parse(redirectUrl);
    state = _createCryptoRandomString();
    usePkce = false;
  }

  String? token;

  /// Extract authorization code in Code flow, see:
  @override
  bool checkUrl(Uri url) {
    try {
      if (url.hasFragment && !url.hasQuery) {
        url = url.replace(query: url.fragment);
      }

      if (!url.toString().contains(redirectUri.toString())) return false;
      if (url.query.isEmpty) return false;

      // verify state
      if (!url.queryParameters.containsKey('state') || url.queryParameters['state'] != state) return false;

      // verify code
      if (!url.queryParameters.containsKey(authCodeKey)) return false;
      var code = url.queryParameters[authCodeKey];
      if (code?.isEmpty ?? true) return false;
      token = code;
      foundAuthCode(code);
      return true;
    } catch (exception) {
      print(exception);
      return false;
    }
  }


  /// Init query to get authorization code, see
  /// https://developer.box.com/guides/authentication/oauth2/without-sdk/#1-build-authorization-url
  @override
  Future<Map<String, dynamic>> getInitialUrlQueryParameters() async {
    var data = await super.getInitialUrlQueryParameters();
    if (state.isNotEmpty) {
      data["state"] = state;
    }
    return data;
  }

  /// Gets the data that will be posted to swap the auth code for an auth token, see
  /// https://developer.box.com/guides/authentication/oauth2/without-sdk/#4-exchange-code
  @override
  Future<Map<String, dynamic>> getTokenPostData(String? clientSecret) async {
    var map = {
      "grant_type": "authorization_code",
      "client_id": clientId,
      'client_secret': clientSecret,
      authCodeKey: authCode,
    };
    if (usePkce!) {
      map["code_verifier"] = verifier;
    }
    return map;
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
      return Random(DateTime
          .now()
          .millisecondsSinceEpoch);
    }
  }
}
