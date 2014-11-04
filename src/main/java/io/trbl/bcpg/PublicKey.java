package io.trbl.bcpg;

public interface PublicKey extends Key {

  byte[] getFingerprint();

}
