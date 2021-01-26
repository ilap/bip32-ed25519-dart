import 'helpers/signature_benchmark.dart';

void main() {
  SignatureBenchmark('Bip32Ed25519  (1K)', true, 1024).report();
  SignatureBenchmark('Bip32Ed25519  (1K)', false, 1024).report();

  SignatureBenchmark('Bip32Ed25519  (4K)', true, 1024 * 4).report();
  SignatureBenchmark('Bip32Ed25519  (4K)', false, 1024 * 4).report();

  SignatureBenchmark('Bip32Ed25519 (16K)', true, 1024 * 16).report();
  SignatureBenchmark('Bip32Ed25519 (16K)', false, 1024 * 16).report();

  SignatureBenchmark('Bip32Ed25519 (64K)', true, 1024 * 64).report();
  SignatureBenchmark('Bip32Ed25519 (64K)', false, 1024 * 64).report();
}
