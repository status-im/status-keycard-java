package im.status.keycard.applet;

import im.status.keycard.io.APDUCommand;
import im.status.keycard.io.APDUResponse;
import im.status.keycard.io.CardChannel;

import java.io.IOException;

/**
 * Command set for the Ident applet.
 */
public class IdentCommandSet {
  private final CardChannel apduChannel;

  /**
   * Creates a IdentCommandSet using the given APDU Channel
   * @param apduChannel APDU channel
   */
  public IdentCommandSet(CardChannel apduChannel) {
    this.apduChannel = apduChannel;
  }

  /**
   * Selects a Cash instance. The applet is assumed to have been installed with its default AID. The returned data is
   * a public key which must be used to initialize the secure channel.
   *
   * @return the raw card response
   * @throws IOException communication error
   */
  public APDUResponse select() throws IOException {
    APDUCommand selectApplet = new APDUCommand(0x00, 0xA4, 4, 0, Identifiers.IDENT_INSTANCE_AID);
    return apduChannel.send(selectApplet);
  }

  /**
   * Sends a STORE DATA APDU.
   *
   * @param data the data to sign
   * @return the raw card response
   * @throws IOException communication error
   */
  public APDUResponse storeData(byte[] data) throws IOException {
    APDUCommand sign = new APDUCommand(0x80, KeycardCommandSet.INS_STORE_DATA, 0x00, 0x00, data);
    return apduChannel.send(sign);
  }
}
