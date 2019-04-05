package im.status.keycard.globalplatform;

/**
 * Keeps keys for SCP02.
 */
public class SCP02Keys {
  public byte[] encKeyData;
  public byte[] macKeyData;
  public byte[] dekKeyData;

  /**
   * Constructor. Takes the ENC and MAC keys.
   *
   * @param encKeyData encryption key
   * @param macKeyData mac key
   * @param dekKeyData data encryption key
   */
  public SCP02Keys(byte[] encKeyData, byte[] macKeyData, byte[] dekKeyData) {
    this.encKeyData = encKeyData;
    this.macKeyData = macKeyData;
    this.dekKeyData = dekKeyData;
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

  /**
   * The DEK key
   *
   * @return the DEK key
   */
  public byte[] getDekKeyData() {
    return dekKeyData;
  }
}
