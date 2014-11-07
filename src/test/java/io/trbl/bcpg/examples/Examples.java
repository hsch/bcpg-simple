package io.trbl.bcpg.examples;

import io.trbl.bcpg.KeyFactory;
import io.trbl.bcpg.KeyFactoryFactory;
import io.trbl.bcpg.PublicKey;
import io.trbl.bcpg.SecretKey;
import io.trbl.bcpg.SecretTransform;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

import org.junit.BeforeClass;
import org.junit.Test;

public class Examples {

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

  @Test
  public void begin() throws Exception {
    final KeyFactory keyFactory = KeyFactoryFactory.newInstance();
    keyFactory.generateKeyPair("bob", "my secret passphrase".toCharArray());
  }

  @Test
  public void Generating_A_Key_Pair() throws Exception {
    final SecretKey secretKey = keyFactory.generateKeyPair("bob", "my secret passphrase".toCharArray());
    System.out.println(secretKey.getPublicKey().toArmoredString());
    System.out.println(secretKey.toArmoredString());
  }

  @Test
  public void Loading_Existing_Keys() throws Exception {
    {
      final String otherPersonsAsciiPublicKey = "..."; // Have your ASCII-armored public key here
      final PublicKey otherPersonsPublicKey = keyFactory.parsePublicKey(otherPersonsAsciiPublicKey);
    }
    {
      final String myAsciiSecretKey = "..."; // Have your ASCII-armored secret key here
      final SecretKey mySecretKey = keyFactory.parseSecretKey(myAsciiSecretKey);
    }
  }

  @Test
  public void Encrypting_Data() throws Exception {
    final SecretTransform transform = mySecretKey.signEncryptFor(otherPersonsAsciiPublicKey);
    final char[] myPassphrase = "my secret passphrase".toCharArray();
    final byte[] myPlainText = "Hello, World!".getBytes();
    transform.run(myPassphrase, new ByteArrayInputStream(myPlainText), System.out);
  }

  @Test
  public void Decrypting_Data() throws Exception {
    final SecretTransform transform = mySecretKey.decryptVerifyFrom(otherPersonsAsciiPublicKey);
    final char[] myPassphrase = "my secret passphrase".toCharArray();
    final byte[] encryptedMessage = "...".getBytes(); // Have an ASCII-armored encrypted message here
    transform.run(myPassphrase, new ByteArrayInputStream(Examples.encryptedMessage), System.out);
  }

}
