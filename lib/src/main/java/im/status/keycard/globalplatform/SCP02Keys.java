package im.status.keycard.globalplatform;

/**
 * Keeps keys for SCP02.
 */
public class SCP02Keys {
  public byte[] encKeyData;
  public byte[] macKeyData;

  /**
   * Constructor. Takes the ENC and MAC keys.
   *
   * @param encKeyData encryption key
   * @param macKeyData mac key
   */
  public SCP02Keys(byte[] encKeyData, byte[] macKeyData) {
    this.encKeyData = encKeyData;
    this.macKeyData = macKeyData;
  }

  /**
   * The encryption key
   * @return the encryption key
   */
  public byte[] getEncKeyData() {
    return encKeyData;
  }

  /**
   * The MAC key
   *
   * @return the MAC key
   */
  public byte[] getMacKeyData() {
    return macKeyData;
  }
}
