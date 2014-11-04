package io.trbl.bcpg;

import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.openpgp.PGPPublicKey;

class BcPGPPublicKey implements PublicKey {

  private final PGPPublicKey publicKey;

  public BcPGPPublicKey(final PGPPublicKey publicKey) {
    this.publicKey = publicKey;
  }

  public String toArmoredString() {
    final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    final ArmoredOutputStream armoredStream = new ArmoredOutputStream(outputStream);
    final BufferedOutputStream bufferedStream = new BufferedOutputStream(armoredStream);
    try {
      publicKey.encode(bufferedStream);
      bufferedStream.close();
    }
    catch (final IOException e) {
    }
    return outputStream.toString();
  }

  public byte[] getFingerprint() {
    return publicKey.getFingerprint();
  }

}
