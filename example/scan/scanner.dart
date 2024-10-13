// ignore_for_file: one_member_abstracts

import 'dart:async';
import 'package:http/http.dart' as http;

class BlockFrost implements Scanner {
  BlockFrost(this.url);
  BlockFrost.withDefaultUrl() : url = BlockFrost.defaultUrl;

  static const String defaultUrl =
      'https://cardano-preview.blockfrost.io/api/v0';
  static const Map<String, String> defaultHeaders = {
    'User-Agent': 'Dart bip32_ed25519_dart library',
    'project_id': 'FIXME: ADD BLOCKFROST PROJECT IT HERE'
  };

  final String url;

  @override
  Future<bool> present(String address) async {
    final uri = Uri.parse('$url/addresses/$address');
    final response = await http.get(uri, headers: defaultHeaders);
    print('Resp code: ${response.statusCode}, Body:\n ${response.body}');

    return response.statusCode == 200;
  }
}

List<Scanner> scanners = [BlockFrost.withDefaultUrl()];

abstract class Scanner {
  Future<bool> present(String address);
}
