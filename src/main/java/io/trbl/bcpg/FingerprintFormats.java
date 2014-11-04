package io.trbl.bcpg;

public final class FingerprintFormats {

  public static final FingerprintFormat GPG = new SimpleFingerprintFormat(2, " ", 10, "  ");
  public static final FingerprintFormat GPG_MULTILINE = new SimpleFingerprintFormat(2, " ", 10, "\n");
  public static final FingerprintFormat SSH = new SimpleFingerprintFormat(1, ":");

}
