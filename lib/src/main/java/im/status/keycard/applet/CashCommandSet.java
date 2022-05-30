package im.status.keycard.applet;

import im.status.keycard.io.APDUCommand;
import im.status.keycard.io.APDUResponse;
import im.status.keycard.io.CardChannel;

import java.io.IOException;

/**
 * Command set for the Cash applet.
 */
public class CashCommandSet {
  private final CardChannel apduChannel;

  /**
   * Creates a CashCommandSet using the given APDU Channel
   * @param apduChannel APDU channel
   */
  public CashCommandSet(CardChannel apduChannel) {
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
    APDUCommand selectApplet = new APDUCommand(0x00, 0xA4, 4, 0, Identifiers.CASH_INSTANCE_AID);
    return apduChannel.send(selectApplet);
  }

  /**
   * Sends a SIGN APDU.
   *
   * @param data the data to sign
   * @return the raw card response
   * @throws IOException communication error
   */
  public APDUResponse sign(byte[] data, byte p2) throws IOException {
    APDUCommand sign = new APDUCommand(0x80, KeycardCommandSet.INS_SIGN, 0x00, p2, data);
    return apduChannel.send(sign);
  }

  /**
   * Sends a SIGN APDU. This signs a precomputed hash with ECDSA so the input must be exactly 32-bytes long.
   *
   * @param data the data to sign
   * @return the raw card response
   * @throws IOException communication error
   */
  public APDUResponse sign(byte[] data) throws IOException {
    return sign(data, KeycardCommandSet.SIGN_P2_ECDSA);
  }

  /**
   * Sends a SIGN APDU. The message can be any length, and it is mapped to a point on G2 internally.
   *
   * @param data the data to sign
   * @return the raw card response
   * @throws IOException communication error
   */
  public APDUResponse signBLS(byte[] data) throws IOException {
    return sign(BLS.hash(data), KeycardCommandSet.SIGN_P2_BLS12_381);
  }
}
