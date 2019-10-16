package im.status.keycard.applet;

/**
 * Parses the response from a SELECT command sent to the Cash applet.
 */
public class CashApplicationInfo {
  public static final byte TLV_PUB_DATA = (byte) 0x82;

  private byte[] pubKey;
  private short appVersion;
  private byte[] pubData;

  /**
   * Constructs an object by parsing the TLV data.
   *
   * @param tlvData the raw response data from the card
   * @throws IllegalArgumentException the TLV does not follow the allowed format
   */
  public CashApplicationInfo(byte[] tlvData) throws IllegalArgumentException {
    TinyBERTLV tlv = new TinyBERTLV(tlvData);

    tlv.enterConstructed(ApplicationInfo.TLV_APPLICATION_INFO_TEMPLATE);
    pubKey = tlv.readPrimitive(ApplicationInfo.TLV_PUB_KEY);
    appVersion = (short) tlv.readInt();
    pubData = tlv.readPrimitive(TLV_PUB_DATA);
  }

  /**
   * The public key of the wallet.
   *
   * @return the public key
   */
  public byte[] getPubKey() {
    return pubKey;
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
    return ApplicationInfo.getAppVersionString(appVersion);
  }

  /**
   * The public data of the cash applet.
   *
   * @return the public key
   */
  public byte[] getPubData() {
    return pubData;
  }
}
