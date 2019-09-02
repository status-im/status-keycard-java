package im.status.keycard.applet;

import org.bouncycastle.crypto.digests.KeccakDigest;

import java.util.Arrays;

public class Ethereum {
  private Ethereum() {

  }

  public static byte[] toEthereumAddress(byte[] publicKey) {
    KeccakDigest digest = new KeccakDigest(256);
    digest.update(publicKey, 1, (publicKey.length - 1));
    byte[] hash = new byte[32];
    digest.doFinal(hash, 0);
    return Arrays.copyOfRange(hash,12, hash.length);
  }
}
