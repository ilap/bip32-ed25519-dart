import 'dart:async';
import 'dart:convert';
import 'package:http/http.dart' as http;

// Koios Scanner Implementation
class KoiosScanner implements Scanner {
  KoiosScanner(this.url);
  KoiosScanner.withDefaultUrl() : url = KoiosScanner.defaultUrl;

  static const String defaultUrl = 'https://preview.koios.rest/api/v1';
  static const Map<String, String> defaultHeaders = {
    'Accept': 'application/json',
  };

  final String url;

  @override
  Future<bool> present(String address) async {
    final uri = Uri.parse('$url/address_utxos');
    final payload = {
      "_addresses": [address]
    };

    final body = json.encode(payload);

    final response = await http.post(
      uri,
      headers: {...defaultHeaders, 'Content-Type': 'application/json'},
      body: body,
    );

    return response.statusCode == 200;
  }
}

List<Scanner> scanners = [KoiosScanner.withDefaultUrl()];

abstract class Scanner {
  Future<bool> present(String address);
}
