package io.trbl.bcpg;

public class SimpleFingerprintFormat implements FingerprintFormat {

  private final int minorGroupSize;
  private final String minorDelimiter;
  private final int majorGroupSize;
  private final String majorDelimiter;

  public SimpleFingerprintFormat() {
    this(0, "", 0, "");
  }

  public SimpleFingerprintFormat(final int groupSize, final String delimiter) {
    this(groupSize, delimiter, 0, "");
  }

  public SimpleFingerprintFormat(final int minorGroupSize, final String minorDelimiter, final int majorGroupSize, final String majorDelimiter) {
    this.minorGroupSize = minorGroupSize;
    this.minorDelimiter = minorDelimiter;
    this.majorGroupSize = majorGroupSize;
    this.majorDelimiter = majorDelimiter;
  }

  public String format(final byte[] fingerprint) {
    final StringBuilder result = new StringBuilder();
    for (int i = 0; i < fingerprint.length; ++i) {
      if (i > 0) {
        if (majorGroupSize != 0 && i % majorGroupSize == 0) {
          result.append(majorDelimiter);
        }
        else if (minorGroupSize != 0 && i % minorGroupSize == 0) {
          result.append(minorDelimiter);
        }
      }
      result.append(String.format("%02X", fingerprint[i]));
    }
    return result.toString();
  }

}
