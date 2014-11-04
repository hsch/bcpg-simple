package io.trbl.bcpg;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Iterator;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignature;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSignatureList;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

class BcPGPDecryptVerifyTransform implements SecretTransform {

  private final PGPPublicKey publicKey;
  private final PGPSecretKey secretKey;

  public BcPGPDecryptVerifyTransform(final PGPPublicKey publicKey, final PGPSecretKey secretKey) {
    this.publicKey = publicKey;
    this.secretKey = secretKey;
  }

  public void run(final char[] passphrase, final InputStream inputStream, final OutputStream out) throws IOException, CryptoException {
    try {
      // final PGPObjectFactory pgpF = new PGPObjectFactory(new ArmoredInputStream(inputStream), new
      // BcKeyFingerprintCalculator());
      final PGPEncryptedDataList enc = BcPGPUtils.extractPGPObject(PGPEncryptedDataList.class, inputStream);

      // final Object o = pgpF.nextObject();
      //
      // the first object might be a PGP marker packet.
      //
      // if (o instanceof PGPEncryptedDataList) {
      // enc = (PGPEncryptedDataList) o;
      // }
      // else {
      // enc = (PGPEncryptedDataList) pgpF.nextObject();
      // }

      final PGPPrivateKey privateKey = secretKey.extractPrivateKey(new JcePBESecretKeyDecryptorBuilder().setProvider(new BouncyCastleProvider())
          .build(passphrase));

      final Iterator<?> it = enc.getEncryptedDataObjects();
      final PGPPublicKeyEncryptedData pbe = (PGPPublicKeyEncryptedData) it.next();

      PGPObjectFactory pgpFact = new PGPObjectFactory(pbe.getDataStream(new BcPublicKeyDataDecryptorFactory(privateKey)),
          new BcKeyFingerprintCalculator());

      final PGPCompressedData c1 = (PGPCompressedData) pgpFact.nextObject();

      pgpFact = new PGPObjectFactory(c1.getDataStream(), new BcKeyFingerprintCalculator());

      final PGPOnePassSignatureList p1 = (PGPOnePassSignatureList) pgpFact.nextObject();

      final PGPOnePassSignature ops = p1.get(0);

      final PGPLiteralData p2 = (PGPLiteralData) pgpFact.nextObject();

      final InputStream dIn = p2.getInputStream();
      int ch;

      try {
        // new BcPGPContentSignerBuilder(SymmetricKeyAlgorithmTags.AES_128,
        // HashAlgorithmTags.SHA1).build(PGPSignature.BINARY_DOCUMENT, sKey)
        ops.init(new BcPGPContentVerifierBuilderProvider(), publicKey);
      }
      catch (final Exception e) {
        // TODO Auto-generated catch block
        e.printStackTrace();
      }

      while ((ch = dIn.read()) >= 0) {
        ops.update((byte) ch);
        out.write(ch);
      }

      final PGPSignatureList p3 = (PGPSignatureList) pgpFact.nextObject();

      if (ops.verify(p3.get(0))) {
        System.out.println("signature verified.");
      }
      else {
        System.out.println("signature verification failed.");
      }
    }
    catch (final Exception e) {
      throw new CryptoException(e);
    }
  }

}
