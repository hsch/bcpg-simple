package io.trbl.bcpg;

public interface KeyFactory {

  SecretKey generateKeyPair(String id, char[] passphrase) throws CryptoException;

  SecretKey parseSecretKey(String secretKey);

  PublicKey parsePublicKey(String publicKey);

}
