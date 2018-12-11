package im.status.keycard.globalplatform;

import java.io.IOException;

import im.status.keycard.io.APDUCommand;
import im.status.keycard.io.APDUException;
import im.status.keycard.io.APDUResponse;
import im.status.keycard.io.CardChannel;

/**
 * An SCP02 Secure Channel. Wraps a CardChannel to allow transparent handling of the scure channel.
 */
public class SecureChannel {
  private CardChannel channel;
  private SCP02Wrapper wrapper;

  public static byte[] DERIVATION_PURPOSE_ENC = new byte[]{(byte) 0x01, (byte) 0x82};
  public static byte[] DERIVATION_PURPOSE_MAC = new byte[]{(byte) 0x01, (byte) 0x01};
  public static byte[] DERIVATION_PURPOSE_DEK = new byte[]{(byte) 0x01, (byte) 0x81};

  /**
   * Constructs an SCP02 secure channel, wrapping a regular CardChannel.
   *
   * @param channel the channel to wrap
   * @param keys the keys
   */
  public SecureChannel(CardChannel channel, SCP02Keys keys) {
    this.channel = channel;
    this.wrapper = new SCP02Wrapper(keys.getMacKeyData());
  }

  /**
   * Protects the given command with SCP02 and forwards it to the underlying CardChannel.
   *
   * @param cmd the command to send
   * @return the response from the card
   *
   * @throws IOException communication error
   */
  public APDUResponse send(APDUCommand cmd) throws IOException {
    APDUCommand wrappedCommand = this.wrapper.wrap(cmd);
    return this.channel.send(wrappedCommand);
  }

  /**
   * Verifies the card challenge and builds an SCP02 session object.
   *
   * @param hostChallenge the host challenge
   * @param cardKeys the SCP02 keys
   * @param resp the response from the card to the INITIALIZE UPDATE oommand
   * @return the Session object built on succesful verification
   * @throws APDUException communication error
   */
  public static Session verifyChallenge(byte[] hostChallenge, SCP02Keys cardKeys, APDUResponse resp) throws APDUException {
    if (resp.getSw() == APDUResponse.SW_SECURITY_CONDITION_NOT_SATISFIED) {
      throw new APDUException(resp.getSw(), "security condition not satisfied");
    }

    if (resp.getSw() == APDUResponse.SW_AUTHENTICATION_METHOD_BLOCKED) {
      throw new APDUException(resp.getSw(), "authentication method blocked");
    }

    byte[] data = resp.getData();

    if (data.length != 28) {
      throw new APDUException(resp.getSw(), String.format("bad data length, expected 28, got %d", data.length));
    }

    byte[] cardChallenge = new byte[8];
    System.arraycopy(data, 12, cardChallenge, 0, 8);

    byte[] cardCryptogram = new byte[8];
    System.arraycopy(data, 20, cardCryptogram, 0, 8);

    byte[] seq = new byte[2];
    System.arraycopy(data, 12, seq, 0, 2);

    byte[] sessionEncKey = Crypto.deriveSCP02SessionKey(cardKeys.getEncKeyData(), seq, DERIVATION_PURPOSE_ENC);
    byte[] sessionMacKey = Crypto.deriveSCP02SessionKey(cardKeys.getMacKeyData(), seq, DERIVATION_PURPOSE_MAC);

    SCP02Keys sessionKeys = new SCP02Keys(sessionEncKey, sessionMacKey);

    boolean verified = Crypto.verifyCryptogram(sessionKeys.getEncKeyData(), hostChallenge, cardChallenge, cardCryptogram);
    if (!verified) {
      throw new APDUException("error verifying card cryptogram.");
    }

    return new Session(sessionKeys, cardChallenge);
  }
}
