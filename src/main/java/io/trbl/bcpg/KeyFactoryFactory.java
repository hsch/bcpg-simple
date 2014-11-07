package io.trbl.bcpg;

public class KeyFactoryFactory {

  static {
    if (!Boolean.getBoolean("skipCryptoWarning")) {
      System.err.println();
      System.err.println("(!) This software applies cryptographic methods without being verified");
      System.err.println("    by security professionals. Please, be careful.");
      System.err.println();
    }
  }

  /**
   * This method creates a new instance of a {@link KeyFactory}.
   */
  public static KeyFactory newInstance() {
    return new BcPGPKeyFactory();
  }

}
