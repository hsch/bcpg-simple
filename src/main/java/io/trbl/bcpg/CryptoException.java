package io.trbl.bcpg;

public class CryptoException extends Exception {

  private static final long serialVersionUID = 1L;

  public CryptoException(final Exception e) {
    super(e);
  }

}
