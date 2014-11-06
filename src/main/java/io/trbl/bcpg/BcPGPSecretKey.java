package io.trbl.bcpg;

import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;

class BcPGPSecretKey implements SecretKey {

  private final PGPSecretKey secretKey;

  public BcPGPSecretKey(final PGPSecretKey pgpKey) {
    this.secretKey = pgpKey;
  }

  public String toArmoredString() {
    final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    final ArmoredOutputStream armoredStream = new ArmoredOutputStream(outputStream);
    final BufferedOutputStream bufferedStream = new BufferedOutputStream(armoredStream);
    try {
      secretKey.encode(bufferedStream);
      bufferedStream.close();
    }
    catch (final IOException e) {
    }
    return outputStream.toString();
  }

  public PublicKey getPublicKey() {
    return new BcPGPPublicKey(secretKey.getPublicKey());
  }

  public SecretTransform signEncryptFor(final String publicKeyInputStream) throws IOException {
    return new BcPGPSignEncryptTransform(BcPGPUtils.extractPGPObject(PGPPublicKeyRing.class, publicKeyInputStream).getPublicKey(), secretKey);
  }

  public SecretTransform decryptVerifyFrom(final String publicKeyInputStream) throws IOException {
    return new BcPGPDecryptVerifyTransform(BcPGPUtils.extractPGPObject(PGPPublicKeyRing.class, publicKeyInputStream).getPublicKey(), secretKey);
  }

}
