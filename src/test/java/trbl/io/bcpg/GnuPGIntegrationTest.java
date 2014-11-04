package trbl.io.bcpg;

import io.trbl.bcpg.KeyFactoryFactory;
import io.trbl.bcpg.SecretKey;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.OutputStream;

import org.junit.Assert;
import org.junit.Test;

import trbl.io.gnupg.GnuPG;
import trbl.io.gnupg.GnuPGAgent;

public class GnuPGIntegrationTest {

  private static final String SENDER_ID = "sender@trbl.io";
  private static final char[] SENDER_PASSPHRASE = "hello-sender".toCharArray();

  private static final String RECIPIENT_ID = "recipient@trbl.io";
  private static final char[] RECIPIENT_PASSPHRASE = "hello-recipient".toCharArray();

  private static final byte[] MESSAGE = "Hello, World.\n".getBytes();

  @Test
  public void signEncryptToGnuPG() throws Exception {
    final GnuPGAgent gnuPgAgent = GnuPGAgent.newInstance();
    try {

      final GnuPG gnuPg = gnuPgAgent.newGnuPG();
      gnuPg.generateKeys(RECIPIENT_ID, RECIPIENT_PASSPHRASE);

      final String recipientPublicKey = gnuPg.export(RECIPIENT_ID);

      final SecretKey senderKey = KeyFactoryFactory.newInstance().generateKeyPair(SENDER_ID, SENDER_PASSPHRASE);
      final File senderPublicKey = gnuPg.newTempFile();
      final OutputStream outputStream = new FileOutputStream(senderPublicKey);
      try {
        outputStream.write(senderKey.getPublicKey().toArmoredString().getBytes());
      }
      finally {
        outputStream.close();
      }

      gnuPg.importKey(senderPublicKey);

      final File encryptedDataFile = gnuPg.newTempFile();
      final OutputStream encryptedDataStream = new FileOutputStream(encryptedDataFile);
      try {
        senderKey.signEncrypt(recipientPublicKey).run(SENDER_PASSPHRASE, new ByteArrayInputStream(MESSAGE), encryptedDataStream);
      }
      finally {
        encryptedDataStream.close();
      }

      final String decryptionResult = gnuPg.decrypt(encryptedDataFile, RECIPIENT_PASSPHRASE);
      Assert.assertArrayEquals(MESSAGE, decryptionResult.getBytes());

    }
    finally {
      gnuPgAgent.close();
    }
  }

  @Test
  public void decryptVerifyFromGnuPG() throws Exception {
    final GnuPGAgent agent = GnuPGAgent.newInstance();
    try {

      final GnuPG gnuPg = agent.newGnuPG();
      gnuPg.generateKeys(SENDER_ID, SENDER_PASSPHRASE);

      final String senderPublicKey = gnuPg.export(SENDER_ID);

      final SecretKey recipientKey = KeyFactoryFactory.newInstance().generateKeyPair(RECIPIENT_ID, RECIPIENT_PASSPHRASE);
      final File recipientPublicKey = gnuPg.newTempFile();
      final OutputStream outputStream = new FileOutputStream(recipientPublicKey);
      try {
        outputStream.write(recipientKey.getPublicKey().toArmoredString().getBytes());
      }
      finally {
        outputStream.close();
      }

      gnuPg.importKey(recipientPublicKey);

      final File plainDataFile = gnuPg.newTempFile();
      final OutputStream writer = new FileOutputStream(plainDataFile);
      try {
        writer.write(MESSAGE);
      }
      finally {
        writer.close();
      }

      final File encryptedDataFile = gnuPg.newTempFile();
      gnuPg.encrypt(RECIPIENT_ID, plainDataFile, encryptedDataFile, SENDER_PASSPHRASE);

      final ByteArrayOutputStream result = new ByteArrayOutputStream();
      recipientKey.decryptVerify(senderPublicKey).run(RECIPIENT_PASSPHRASE, new FileInputStream(encryptedDataFile), result);

      Assert.assertArrayEquals(MESSAGE, result.toByteArray());

    }
    finally {
      agent.close();
    }
  }
}
