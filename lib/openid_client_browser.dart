import 'openid_client.dart';
import 'dart:html' hide Credential, Client;
import 'dart:async';
import 'dart:convert';
export 'openid_client.dart';

class Authenticator {
  final Flow flow;

  final Future<Credential> credential;

  Authenticator._(this.flow) : credential = _credentialFromUri(flow);

  Authenticator(Client client, {Iterable<String> scopes = const []})
      : this._(Flow.implicit(client,
            state: window.localStorage['openid_client:state'])
          ..scopes.addAll(scopes)
          ..redirectUri = Uri.parse(window.location.href).removeFragment());

  void authorize() {
    _clearState();
    window.localStorage['openid_client:state'] = flow.state;
    window.location.href = flow.authenticationUri.toString();
  }

  void _clearState() {
    Platform.supportsTypedData;
    window.localStorage.remove('openid_client:state');
    window.localStorage.remove('openid_client:auth');
  }

  Future logout() async {
    _clearState();
    var creds = await credential;
    await creds.logout();
  }

  static Future<Credential> _credentialFromUri(Flow flow) async {
    Map q;
    if (window.localStorage.containsKey('openid_client:auth')) {
      q = json.decode(window.localStorage['openid_client:auth']);
    } else {
      var uri = Uri(query: Uri.parse(window.location.href).fragment.replaceFirst("/", ""));
      q = uri.queryParameters;
      if (q.containsKey('access_token') ||
          q.containsKey('code') ||
          q.containsKey('id_token')) {
        window.localStorage['openid_client:auth'] = json.encode(q);
        window.history.replaceState('', document.title, window.location.origin + window.location.pathname + window.location.search);
      }
    }
    try {
      var c = await flow.callback(q.cast());
      return c;
    } on ArgumentError {
      return null;
    }
  }
}
