package io.trbl.bcpg;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public interface SecretTransform {

  void run(char[] passphrase, InputStream inputStream, OutputStream outputStream) throws CryptoException, IOException;

}
