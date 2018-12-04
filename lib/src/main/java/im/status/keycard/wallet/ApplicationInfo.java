package im.status.keycard.wallet;

/**
 * Parses the response from a SELECT command. If the card has not yet received the INIT command the isInitializedCard
 * will return false and only the getSecureChannelPubKey method will return a valid value.
 */
public class ApplicationInfo {
  private boolean initializedCard;
  private byte[] instanceUID;
  private byte[] secureChannelPubKey;
  private short appVersion;
  private byte freePairingSlots;
  private byte[] keyUID;

  public static final byte TLV_APPLICATION_INFO_TEMPLATE = (byte) 0xA4;
  public static final byte TLV_PUB_KEY = (byte) 0x80;
  public static final byte TLV_UID = (byte) 0x8F;
  public static final byte TLV_KEY_UID = (byte) 0x8E;

  /**
   * Constructs an object by parsing the TLV data.
   *
   * @param tlvData the raw response data from the card
   * @throws IllegalArgumentException the TLV does not follow the allowed format
   */
  public ApplicationInfo(byte[] tlvData) throws IllegalArgumentException {
    TinyBERTLV tlv = new TinyBERTLV(tlvData);

    int topTag = tlv.readTag();
    tlv.unreadLastTag();

    if (topTag == TLV_PUB_KEY) {
      secureChannelPubKey = tlv.readPrimitive(TLV_PUB_KEY);
      initializedCard = false;
      return;
    }

    tlv.enterConstructed(TLV_APPLICATION_INFO_TEMPLATE);
    instanceUID = tlv.readPrimitive(TLV_UID);
    secureChannelPubKey = tlv.readPrimitive(TLV_PUB_KEY);
    appVersion = (short) tlv.readInt();
    freePairingSlots = (byte) tlv.readInt();
    keyUID = tlv.readPrimitive(TLV_KEY_UID);
    initializedCard = true;
  }

  /**
   * Returns if the card is initialized or not. If this method returns false, only the getSecureChannelPubKey method
   * will return a valid value.
   *
   * @return true if initialized, false otherwise
   */
  public boolean isInitializedCard() {
    return initializedCard;
  }

  /**
   * Utility method to discover if the card has a master key.
   *
   * @return true if the card has a master key, false otherwise
   */
  public boolean hasMasterKey() {
    return keyUID.length != 0;
  }

  /**
   * The instance UID of the applet. This ID never changes for the lifetime of the applet.
   *
   * @return the instance UID
   */
  public byte[] getInstanceUID() {
    return instanceUID;
  }

  /**
   * The public key to be used for secure channel opening. Usually handled internally by the KeycardCommandSet.
   *
   * @return the public key
   */
  public byte[] getSecureChannelPubKey() {
    return secureChannelPubKey;
  }

  /**
   * The application version, encoded as a short. The msb is the major revision number and the lsb is the minor one.
   *
   * @return the application version
   */
  public short getAppVersion() {
    return appVersion;
  }

  /**
   * A formatted application version.
   * @return the string representation of the application version
   */
  public String getAppVersionString() {
    return (appVersion >> 8) + "." + (appVersion & 0xff);
  }

  /**
   * The number of remaining pairing slots. If zero is returned, no further pairing is possible.
   * @return
   */
  public byte getFreePairingSlots() {
    return freePairingSlots;
  }

  /**
   * The UID of the master key on this card. Changes every time a different master key is stored. It has zero length if
   * no key is on the card.
   *
   * @return the Key UID.
   */
  public byte[] getKeyUID() {
    return keyUID;
  }
}
