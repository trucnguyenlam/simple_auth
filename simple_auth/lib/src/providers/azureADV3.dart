import 'dart:async';
import 'dart:convert';
import 'dart:math';

import "package:http/http.dart" as http;
import 'package:simple_auth/simple_auth.dart';

class AzureADV3Api extends OAuthApi {
  bool? useClientSecret = false;

  AzureADV3Api(String identifier, String clientId, String tokenUrl, String authorizationUrl, String redirectUrl,
      {String clientSecret = 'native',
      List<String>? scopes,
      http.Client? client,
      Converter? converter,
      AuthStorage? authStorage,
      bool useEmbeddedBrowser = false})
      : super.fromIdAndSecret(identifier, clientId, clientSecret,
            client: client, scopes: scopes, converter: converter, authStorage: authStorage) {
    this.tokenUrl = tokenUrl;
    this.authorizationUrl = authorizationUrl;
    this.redirectUrl = redirectUrl;
    this.forceRefresh = true;
    this.scopes = scopes ?? ["basic"];
    useClientSecret = clientSecret != "native";
    this.useEmbeddedBrowser = useEmbeddedBrowser;
  }

  Authenticator getAuthenticator() => AzureADV3Authenticator(
        identifier,
        clientId,
        clientSecret,
        tokenUrl,
        authorizationUrl,
        redirectUrl,
        useClientSecret,
        scopes,
        useEmbeddedBrowser,
      );

  @override
  Future<Map<String, String?>> getRefreshTokenPostData(Account account) async {
    var map = await super.getRefreshTokenPostData(account);
    if (!useClientSecret! && map.containsKey("client_secret")) {
      map.remove("client_secret");
    }
    return map;
  }
}

class AzureADV3Authenticator extends OAuthAuthenticator {
  bool? useClientSecret;
  late Uri redirectUri;
  late String state;

  AzureADV3Authenticator(String? identifier, String? clientId, String? clientSecret, String? tokenUrl, String? baseUrl,
      String? redirectUrl, this.useClientSecret, List<String>? scopes, bool useEmbeddedBrowser)
      : super(identifier, clientId, clientSecret, tokenUrl, baseUrl, redirectUrl) {
    this.useEmbeddedBrowser = useEmbeddedBrowser;
    this.scope = scopes;
    this.authCodeKey = "code";
    this.useNonce = false;
    this.usePkce = true;

    redirectUri = Uri.parse(redirectUrl!);
    state = _createCryptoRandomString();
  }

  String? token;

  /// Extract authorization code in Code flow, see:
  /// https://docs.microsoft.com/en-us/onedrive/developer/rest-api/getting-started/graph-oauth?view=odsp-graph-online#step-1-get-an-authorization-code
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
  /// https://docs.microsoft.com/en-us/onedrive/developer/rest-api/getting-started/graph-oauth?view=odsp-graph-online#step-1-get-an-authorization-code
  @override
  Future<Map<String, dynamic>> getInitialUrlQueryParameters() async {
    var map = await super.getInitialUrlQueryParameters();
    map['response_type'] = "code";
    map["display"] = "touch";
    map["prompt"] = "select_account";

    if (state.isNotEmpty) {
      map["state"] = state;
    }

    if (!useClientSecret! && map.containsKey("client_secret")) {
      map.remove("client_secret");
    }

    return map;
  }

  /// Gets the data that will be posted to swap the auth code for an auth token, see
  /// https://docs.microsoft.com/en-us/onedrive/developer/rest-api/getting-started/graph-oauth?view=odsp-graph-online#step-2-redeem-the-code-for-access-tokens
  @override
  Future<Map<String, dynamic>> getTokenPostData(String? clientSecret) async {
    var map = {
      "grant_type": "authorization_code",
      "client_id": clientId,
      "redirect_uri": redirectUrl,
      authCodeKey: authCode,
    };
    if (usePkce!) {
      map["code_verifier"] = verifier;
    }
    return map;
  }

  Map<String, String> splitFragment(String fragment) {
    List<String> params = fragment.split("&");
    var result = Map<String, String>();
    params.forEach((param) {
      final split = param.split("=");
      result[split[0]] = split[1];
    });
    return result;
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
