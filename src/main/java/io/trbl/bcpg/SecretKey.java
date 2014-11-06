package io.trbl.bcpg;

import java.io.IOException;

public interface SecretKey extends Key {

  PublicKey getPublicKey();

  SecretTransform signEncryptFor(String publicKey) throws IOException;

  SecretTransform decryptVerifyFrom(String publicKey) throws IOException;

}
