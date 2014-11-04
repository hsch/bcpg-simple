package io.trbl.bcpg;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Date;

import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.HashAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.bcpg.sig.Features;
import org.bouncycastle.bcpg.sig.KeyFlags;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.openpgp.PGPEncryptedData;
import org.bouncycastle.openpgp.PGPKeyPair;
import org.bouncycastle.openpgp.PGPKeyRingGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSignature;
import org.bouncycastle.openpgp.PGPSignatureSubpacketGenerator;
import org.bouncycastle.openpgp.operator.PBESecretKeyEncryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyEncryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair;

class BcPGPKeyFactory implements KeyFactory {

  public SecretKey generateKeyPair(final String id, final char[] pass) throws CryptoException {
    try {

      // This object generates individual key-pairs.
      final RSAKeyPairGenerator kpg = new RSAKeyPairGenerator();
      kpg.init(new RSAKeyGenerationParameters(BigInteger.valueOf(0x10001), new SecureRandom(), 2048, 12));

      // First create the master (signing) key with the generator.
      final PGPKeyPair keyPair = new BcPGPKeyPair(PGPPublicKey.RSA_GENERAL, kpg.generateKeyPair(), new Date());

      // Add a self-signature on the id
      final PGPSignatureSubpacketGenerator signhashgen = new PGPSignatureSubpacketGenerator();
      signhashgen.setKeyFlags(true, KeyFlags.CERTIFY_OTHER | KeyFlags.SIGN_DATA | KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE);
      signhashgen.setPreferredCompressionAlgorithms(false, new int[] { CompressionAlgorithmTags.ZIP });
      signhashgen.setPreferredHashAlgorithms(false, new int[] { HashAlgorithmTags.SHA1 });
      signhashgen.setPreferredSymmetricAlgorithms(false, new int[] { SymmetricKeyAlgorithmTags.AES_256 });
      signhashgen.setFeature(false, Features.FEATURE_MODIFICATION_DETECTION);

      // Create a signature on the encryption subkey.
      final PGPSignatureSubpacketGenerator enchashgen = new PGPSignatureSubpacketGenerator();
      enchashgen.setKeyFlags(false, KeyFlags.ENCRYPT_COMMS | KeyFlags.ENCRYPT_STORAGE);

      // Objects used to encrypt the secret key.

      // Finally, create the keyring itself. The constructor
      // takes parameters that allow it to generate the self
      // signature.
      final PGPDigestCalculator sha1Calc = new BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1);
      final PBESecretKeyEncryptor secretKeyEncryptor = new BcPBESecretKeyEncryptorBuilder(PGPEncryptedData.AES_128, sha1Calc).build(pass);
      final BcPGPContentSignerBuilder contentSigner = new BcPGPContentSignerBuilder(keyPair.getPublicKey().getAlgorithm(), HashAlgorithmTags.SHA1);
      final PGPKeyRingGenerator keyRingGen = new PGPKeyRingGenerator(PGPSignature.POSITIVE_CERTIFICATION, keyPair, id, sha1Calc,
          signhashgen.generate(), null, contentSigner, secretKeyEncryptor);

      // return new SimpleKeyPair(new BcPGPPublicKey(publicKeyRing.getPublicKey()),
      return new BcPGPSecretKey(keyRingGen.generateSecretKeyRing().getSecretKey());
    }
    catch (final Exception e) {
      throw new CryptoException(e);
    }
  }

  public PublicKey parsePublicKey(final String inputStream) {
    return new BcPGPPublicKey(BcPGPUtils.extractPGPObject(PGPPublicKeyRing.class, inputStream).getPublicKey());
  }

  public SecretKey parseSecretKey(final String inputStream) {
    return new BcPGPSecretKey(BcPGPUtils.extractPGPObject(PGPSecretKeyRing.class, inputStream).getSecretKey());
  }

}
