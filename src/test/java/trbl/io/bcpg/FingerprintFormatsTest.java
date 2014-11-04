package trbl.io.bcpg;

import io.trbl.bcpg.FingerprintFormats;

import org.junit.Assert;
import org.junit.Test;

public class FingerprintFormatsTest {

  @Test
  public void testGPGEmpty() {
    Assert.assertEquals("", FingerprintFormats.GPG.format(new byte[] {}));
  }

  @Test
  public void testSSHEmpty() {
    Assert.assertEquals("", FingerprintFormats.SSH.format(new byte[] {}));
  }

  @Test
  public void testGPG() {
    Assert.assertEquals("0001 FEFF", FingerprintFormats.GPG.format(new byte[] { 0x00, 0x01, (byte) 0xfe, (byte) 0xff }));
  }

  @Test
  public void testGPGLong() {
    Assert.assertEquals(
        "0001 0002 0003 0004 0005  0006 0007 0008 0009 000A",
        FingerprintFormats.GPG.format(new byte[] { 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06, 0x00, 0x07, 0x00, 0x08,
            0x00, 0x09, 0x00, 0x0a }));
  }

  @Test
  public void testGPGMultiline() {
    Assert.assertEquals(
        "0001 0002 0003 0004 0005\n0006 0007 0008 0009 000A",
        FingerprintFormats.GPG_MULTILINE.format(new byte[] { 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06, 0x00, 0x07,
            0x00, 0x08, 0x00, 0x09, 0x00, 0x0a }));
  }

  @Test
  public void testSSH() {
    Assert.assertEquals("00:01:FE:FF", FingerprintFormats.SSH.format(new byte[] { 0x00, 0x01, (byte) 0xfe, (byte) 0xff }));
  }

  @Test
  public void testSSHLong() {
    Assert.assertEquals(
        "00:01:00:02:00:03:00:04:00:05:00:06:00:07:00:08:00:09:00:0A",
        FingerprintFormats.SSH.format(new byte[] { 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06, 0x00, 0x07, 0x00, 0x08,
            0x00, 0x09, 0x00, 0x0a }));
  }

}
