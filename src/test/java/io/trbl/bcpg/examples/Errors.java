package io.trbl.bcpg.examples;

import io.trbl.bcpg.CryptoException;
import io.trbl.bcpg.KeyFactory;
import io.trbl.bcpg.KeyFactoryFactory;
import io.trbl.bcpg.PublicKey;
import io.trbl.bcpg.SecretKey;
import io.trbl.bcpg.SecretTransform;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

import org.junit.BeforeClass;
import org.junit.Test;

public class Errors {

  private static KeyFactory keyFactory = null;
  private static SecretKey mySecretKey = null;
  private static String otherPersonsAsciiPublicKey = null;
  private static byte[] encryptedMessage = null;

  @BeforeClass
  public static void setupEnvironment() throws Exception {

    keyFactory = KeyFactoryFactory.newInstance();

    mySecretKey = keyFactory.generateKeyPair("bob", "my secret passphrase".toCharArray());

    final SecretKey otherPersonsKey = keyFactory.generateKeyPair("alice", "my secret passphrase".toCharArray());
    final PublicKey otherPersonsPublicKey = otherPersonsKey.getPublicKey();
    otherPersonsAsciiPublicKey = otherPersonsPublicKey.toArmoredString();

    final SecretTransform transform = otherPersonsKey.signEncryptFor(mySecretKey.getPublicKey().toArmoredString());
    final char[] myPassphrase = "my secret passphrase".toCharArray();
    final byte[] myPlainText = "Hello, World!\n".getBytes();
    final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    transform.run(myPassphrase, new ByteArrayInputStream(myPlainText), outputStream);
    encryptedMessage = outputStream.toByteArray();

  }

  @Test(expected = CryptoException.class)
  public void begin() throws Exception {

    keyFactory.parsePublicKey("whoos");

  }

}
