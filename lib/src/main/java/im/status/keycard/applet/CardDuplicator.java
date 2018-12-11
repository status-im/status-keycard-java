package im.status.keycard.applet;

import im.status.keycard.io.APDUException;
import im.status.keycard.io.CardChannel;

import java.io.IOException;
import java.security.SecureRandom;

/**
 * Class helping with the card duplication process. Depending on the device's role, only some of the methods are relevant.
 *
 * WORK IN PROGRESS, DO NOT USE YET
 */
public class CardDuplicator {
  private byte[] secret;

  /**
   * Creates a CardDuplicator object. Regardless of the role of the device, this object must be kept and used for the
   * entire duplication session. It cannot be reused for multiple sessions.
   */
  public CardDuplicator() {
    secret = new byte[32];
    SecureRandom random = new SecureRandom();
    random.nextBytes(secret);
  }

  private KeycardCommandSet preamble(CardChannel channel, Pairing pairing, String pin) throws IOException, APDUException {
    KeycardCommandSet cmdSet = new KeycardCommandSet(channel);
    cmdSet.select().checkOK();
    cmdSet.setPairing(pairing);
    cmdSet.autoOpenSecureChannel();
    cmdSet.verifyPIN(pin).checkOK();
    return cmdSet;
  }

  /**
   * Starts duplication session. Must be used on all cards taking part of in the duplication process.
   *
   * @param channel the card channel
   * @param pairing the pairing info
   * @param pin the card PIN
   * @param deviceCount the number of devices which will be adding entropy for the key, including this one
   *
   * @throws IOException communication error
   * @throws APDUException unexpected card response
   */
  public void startDuplication(CardChannel channel, Pairing pairing, String pin, int deviceCount) throws IOException, APDUException {
    KeycardCommandSet cmdSet = preamble(channel, pairing, pin);
    cmdSet.duplicateKeyStart(deviceCount, secret).checkOK();
  }

  /**
   * Exports key. Must be used on the card designated as the source for the duplication.
   *
   * @param channel the card channel
   * @param pairing the pairing info
   * @param pin the card PIN
   *
   * @throws IOException communication error
   * @throws APDUException unexpected card response
   */
  public byte[] exportKey(CardChannel channel, Pairing pairing, String pin) throws IOException, APDUException {
    KeycardCommandSet cmdSet = preamble(channel, pairing, pin);
    return cmdSet.duplicateKeyExport().checkOK().getData();
  }

  /**
   * Imports key. Must be used on all cards designated as the target for the duplication.
   * @param channel the card channel
   * @param pairing the pairing info
   * @param pin the user PIN
   * @param key the key to import
   * @return the key UID
   * @throws IOException communication error
   * @throws APDUException unexpected card response
   */
  public byte[] importKey(CardChannel channel, Pairing pairing, String pin, byte[] key) throws IOException, APDUException {
    KeycardCommandSet cmdSet = preamble(channel, pairing, pin);
    return cmdSet.duplicateKeyImport(key).checkOK().getData();
  }

  /**
   * Adds entropy. Must be used on all cards taking part in the backup process. Each device taking part must use this
   * exactly once, except for the device which started the backup.
   *
   * @param channel
   * @throws IOException communication error
   * @throws APDUException unexpected card response
   */
  public void addEntropy(CardChannel channel) throws IOException, APDUException {
    KeycardCommandSet cmdSet = new KeycardCommandSet(channel);
    cmdSet.select().checkOK();
    cmdSet.duplicateKeyAddEntropy(secret).checkOK();
  }

}
