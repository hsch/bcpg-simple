package io.trbl.bcpg;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;

class BcPGPUtils {

  public static <T> T extractPGPObject(final Class<T> type, final String inputStream) {
    try {
      return extractPGPObject(type, new ByteArrayInputStream(inputStream.getBytes()));
    }
    catch (final IOException e) {
      throw new IllegalStateException("", e);
    }
  }

  public static <T> T extractPGPObject(final Class<T> type, final InputStream inputStream) throws IOException {
    final PGPObjectFactory objectFactory = new PGPObjectFactory(new ArmoredInputStream(inputStream), new BcKeyFingerprintCalculator());
    Object object;
    while ((object = objectFactory.nextObject()) != null) {
      if (type.isAssignableFrom(object.getClass())) {
        return type.cast(object);
      }
    }
    throw new IllegalArgumentException("Input text does not contain a PGP object");
  }

}
