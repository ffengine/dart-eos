import 'dart:math';
import 'dart:async';

import 'package:convert/convert.dart';
import 'package:pointycastle/pointycastle.dart';
import 'package:base58check/base58check.dart';
import 'package:base58check/base58.dart';
import "package:pointycastle/ecc/curves/secp256k1.dart";
import 'package:pointycastle/digests/ripemd160.dart';
import 'package:pointycastle/src/utils.dart' as p_utils;

List<int> getRandomIntList(int count, int maxRandIntValue) {
   var randomGenerator;
   try {
      randomGenerator = Random.secure();
   } catch (e) {
      randomGenerator = new Random();
   }
   
   List<int> randomIntList = [];

   for(var i = 0; i < count; i++) {
      int randomNumber = randomGenerator.nextInt( maxRandIntValue ); // [0 ~ 2^8)
      randomIntList.add(randomNumber);
   }
   
   return randomIntList;
}

const EosRandomKeyBits = 256;
const maxRandUInt8Value = 1 << 8; // [0, maxRandInt8)

class EosPrivateKey {
   
   List<int> _randomKey;      // secure random key
   
   EosPrivateKey() {
      _randomKey = getRandomIntList(EosRandomKeyBits ~/ 8, maxRandUInt8Value);
   }

   List<int> get randomKey => _randomKey;
   
   String toWif() {
      const version = 0x80;
      
      final payload = new Base58CheckPayload(version, _randomKey);
      final base58CheckCodec = new Base58CheckCodec.bitcoin();
      return base58CheckCodec.encode(payload);
   }
   
   void fromWif(String wif) {
      _randomKey = [];
      
      final base58CheckCodec = new Base58CheckCodec.bitcoin();
      _randomKey = base58CheckCodec.decode(wif).payload;
   }
   
   String toPublicKey() {
   
      var secp256k1 = new ECCurve_secp256k1();
   
      BigInt privateKeyNum = p_utils.decodeBigInt(this.randomKey);
      ECPoint ecPoint = secp256k1.G * privateKeyNum;
      var encodedBuffer = ecPoint.getEncoded(true);
   
      var ripemd160 = new RIPEMD160Digest();
      var checksum = ripemd160.process(encodedBuffer);
      checksum = checksum.getRange(0, 4).toList();
   
      var base58Codec = new Base58Codec(Base58CheckCodec.BITCOIN_ALPHABET);
      String publicKey = 'EOS' + base58Codec.encode( encodedBuffer + checksum );
   
      return publicKey;
   }
}

// check your results with:
// https://github.com/webdigi/
// https://eostea.github.io/eos-generate-key/
void testEosKeys() {
   
   final privateKey = new EosPrivateKey();
   print ("random key: " + hex.encode(privateKey.randomKey));

   String wif = privateKey.toWif();
   print("wif private key: " + wif + " , length: " + wif.length.toString());
   
   String publicKey = privateKey.toPublicKey();
   print("public key: " + publicKey + " , length: " + publicKey.length.toString());
   
}

void main() {
   testEosKeys();
}

