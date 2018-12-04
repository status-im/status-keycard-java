package im.status.keycard.applet;

/**
 * Parses the result of a GET STATUS command retrieving application status.
 */
public class ApplicationStatus {
  private byte pinRetryCount;
  private byte pukRetryCount;
  private boolean hasMasterKey;

  public static final byte TLV_APPLICATION_STATUS_TEMPLATE = (byte) 0xA3;

  /**
   * Constructor from TLV data
   * @param tlvData the TLV data
   * @throws IllegalArgumentException if the TLV does not follow the expected format
   */
  public ApplicationStatus(byte[] tlvData) throws IllegalArgumentException {
    TinyBERTLV tlv = new TinyBERTLV(tlvData);
    tlv.enterConstructed(TLV_APPLICATION_STATUS_TEMPLATE);
    pinRetryCount = (byte) tlv.readInt();
    pukRetryCount = (byte) tlv.readInt();
    hasMasterKey = tlv.readBoolean();
  }

  /**
   * The available PIN retry count.
   * @return the available PIN retry count
   */
  public byte getPINRetryCount() {
    return pinRetryCount;
  }

  /**
   * The available PUK retry count.
   * @return the available PUK retry count
   */
  public byte getPUKRetryCount() {
    return pukRetryCount;
  }

  /**
   * Whether the card has a master key or not.
   *
   * @return whether the card has a master key or not.
   */
  public boolean hasMasterKey() {
    return hasMasterKey;
  }
}
