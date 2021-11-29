import 'dart:async';
import 'dart:convert';
import 'dart:math';

import "package:http/http.dart" as http;
import 'package:simple_auth/simple_auth.dart';

class DropboxApiV2 extends OAuthApi {
  bool? isUsingNative;

  DropboxApiV2(String identifier, String clientId, String redirectUrl,
      {String clientSecret = "native",
      List<String>? scopes,
      http.Client? client,
      Converter? converter,
      AuthStorage? authStorage,
      bool useEmbeddedBrowser = false})
      : super.fromIdAndSecret(identifier, clientId, clientSecret,
            client: client, scopes: scopes, converter: converter, authStorage: authStorage) {
    this.scopesRequired = false;
    this.tokenUrl = "https://api.dropbox.com/oauth2/token";
    this.baseUrl = "https://api.dropbox.com";
    this.authorizationUrl = "https://www.dropbox.com/oauth2/authorize";
    this.redirectUrl = redirectUrl;
    this.useEmbeddedBrowser = useEmbeddedBrowser;
  }

  @override
  Authenticator getAuthenticator() => DropboxV2Authenticator(
      identifier, clientId, clientSecret, tokenUrl, authorizationUrl, redirectUrl!, scopes, useEmbeddedBrowser);
}

class DropboxV2Authenticator extends OAuthAuthenticator {
  late Uri redirectUri;
  late String state;

  DropboxV2Authenticator(String? identifier, String? clientId, String? clientSecret, String? tokenUrl, String? baseUrl,
      String redirectUrl, List<String>? scopes, bool useEmbeddedBrowser)
      : super(identifier, clientId, clientSecret, tokenUrl, baseUrl, redirectUrl) {
    this.useEmbeddedBrowser = useEmbeddedBrowser;
    redirectUri = Uri.parse(redirectUrl);
    state = _createCryptoRandomString();
    usePkce = true;
  }

  String? token;

  @override
  bool checkUrl(Uri url) {
    try {
      /*
       * If dropbox uses fragments instead of query parameters then swap convert
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

  @override
  Future<Map<String, dynamic>> getInitialUrlQueryParameters() async {
    var data = await super.getInitialUrlQueryParameters();

    // to get refresh token
    data['token_access_type'] = 'offline';
    data['force_reauthentication'] = 'true';

    if (state.isNotEmpty) {
      data["state"] = state;
    }
    return data;
  }

  ///Gets the data that will be posted to swap the auth code for an auth token
  @override
  Future<Map<String, dynamic>> getTokenPostData(String? clientSecret) async {
    var map = {"grant_type": "authorization_code", authCodeKey: authCode, "client_id": clientId};
    map["redirect_uri"] = redirectUrl;
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
      return Random(DateTime.now().millisecondsSinceEpoch);
    }
  }
}
