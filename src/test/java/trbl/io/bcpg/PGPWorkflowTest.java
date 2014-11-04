package trbl.io.bcpg;

import io.trbl.bcpg.KeyFactory;
import io.trbl.bcpg.KeyFactoryFactory;
import io.trbl.bcpg.PublicKey;
import io.trbl.bcpg.SecretKey;

import org.bouncycastle.util.encoders.Hex;
import org.junit.Assert;
import org.junit.Test;

public class PGPWorkflowTest {

  @Test
  public void testOutput() throws Exception {
    final KeyFactory pgpClient = KeyFactoryFactory.newInstance();
    final SecretKey keys = pgpClient.generateKeyPair("me@localhost", new char[] {});
    final PublicKey expectedKey = keys.getPublicKey();
    final String[] lines = expectedKey.toArmoredString().split("[\\r\\n]+");
    Assert.assertTrue("block begins with PGP notice", lines[0].contains("BEGIN PGP PUBLIC KEY BLOCK"));
    Assert.assertTrue("block ends with PGP notice", lines[lines.length - 1].contains("END PGP PUBLIC KEY BLOCK"));
  }

  @Test
  public void testEverything() throws Exception {
    final KeyFactory pgpClient = KeyFactoryFactory.newInstance();
    final SecretKey keys = pgpClient.generateKeyPair("me@localhost", new char[] {});
    final PublicKey expectedKey = keys.getPublicKey();
    final PublicKey actualKey = pgpClient.parsePublicKey(expectedKey.toArmoredString());
    final String expectedFingerprint = new String(Hex.encode(expectedKey.getFingerprint()));
    final String actualFingerPrint = new String(Hex.encode(actualKey.getFingerprint()));
    Assert.assertEquals(expectedFingerprint, actualFingerPrint);
  }

  @Test
  public void testSecret() throws Exception {
    final KeyFactory pgpClient = KeyFactoryFactory.newInstance();
    final SecretKey keys = pgpClient.generateKeyPair("me@localhost", new char[] {});
    System.out.println(keys.getPublicKey().toArmoredString());
  }

}
