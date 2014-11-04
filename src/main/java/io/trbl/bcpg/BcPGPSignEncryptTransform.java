package io.trbl.bcpg;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SecureRandom;
import java.util.Date;
import java.util.Iterator;

import org.bouncycastle.bcpg.ArmoredOutputStream;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureGenerator;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;

class BcPGPSignEncryptTransform implements SecretTransform {

  private final PGPPublicKey publicKey;
  private final PGPSecretKey secretKey;

  public BcPGPSignEncryptTransform(final PGPPublicKey publicKey, final PGPSecretKey secretKey) {
    this.publicKey = publicKey;
    this.secretKey = secretKey;
  }

  public void run(final char[] passphrase, final InputStream inputStream, final OutputStream outputStream) throws IOException, CryptoException {
    try {
      final OutputStream armor = new ArmoredOutputStream(outputStream);

      final PGPEncryptedDataGenerator encryptedDataGenerator = new PGPEncryptedDataGenerator(new JcePGPDataEncryptorBuilder(
          SymmetricKeyAlgorithmTags.AES_128).setWithIntegrityPacket(true).setSecureRandom(new SecureRandom()).setProvider(new BouncyCastleProvider()));
      encryptedDataGenerator.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(publicKey).setSecureRandom(new SecureRandom()).setProvider(
          new BouncyCastleProvider()));

      final OutputStream encryptedOut = encryptedDataGenerator.open(armor, new byte[4096]);

      final PGPCompressedDataGenerator compressedDataGenerator = new PGPCompressedDataGenerator(CompressionAlgorithmTags.ZIP);
      final OutputStream compressedOut = compressedDataGenerator.open(encryptedOut, new byte[4096]);

      final PGPPrivateKey privateKey = secretKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider(new BouncyCastleProvider())
          .build(passphrase));

      final PGPSignatureGenerator signatureGenerator = new PGPSignatureGenerator(new JcaPGPContentSignerBuilder(secretKey.getPublicKey()
          .getAlgorithm(), HashAlgorithmTags.SHA1).setProvider(new BouncyCastleProvider()));
      signatureGenerator.init(PGPSignature.BINARY_DOCUMENT, privateKey);
      final Iterator<?> it = secretKey.getPublicKey().getUserIDs();
      if (it.hasNext()) {
        final PGPSignatureSubpacketGenerator spGen = new PGPSignatureSubpacketGenerator();
        spGen.setSignerUserID(false, (String) it.next());
        signatureGenerator.setHashedSubpackets(spGen.generate());
      }
      signatureGenerator.generateOnePassVersion(false).encode(compressedOut);

      final PGPLiteralDataGenerator literalDataGenerator = new PGPLiteralDataGenerator();
      final OutputStream literalOut = literalDataGenerator.open(compressedOut, PGPLiteralData.BINARY, "", new Date(), new byte[4096]);
      final byte[] buf = new byte[4096];
      for (int len = 0; (len = inputStream.read(buf)) > 0;) {
        literalOut.write(buf, 0, len);
        signatureGenerator.update(buf, 0, len);
      }
      literalDataGenerator.close();
      signatureGenerator.generate().encode(compressedOut);
      compressedDataGenerator.close();
      encryptedDataGenerator.close();
      armor.close();
    }
    catch (final Exception e) {
      throw new CryptoException(e);
    }

  }
}
