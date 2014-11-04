package io.trbl.bcpg;

import java.io.IOException;

public interface SecretKey extends Key {

  PublicKey getPublicKey();

  SecretTransform signEncrypt(String publicKey) throws IOException;

  SecretTransform decryptVerify(String publicKey) throws IOException;

}
