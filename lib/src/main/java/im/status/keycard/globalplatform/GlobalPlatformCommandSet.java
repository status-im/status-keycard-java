package im.status.keycard.globalplatform;

import im.status.keycard.applet.Identifiers;
import org.bouncycastle.util.encoders.Hex;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.SecureRandom;

import im.status.keycard.io.APDUCommand;
import im.status.keycard.io.APDUException;
import im.status.keycard.io.APDUResponse;
import im.status.keycard.io.CardChannel;

/**
 * Command set used for loading, installing and removing applets and packages. This class is generic and can work with
 * any package and applet, but utility methods specific to the Keycard have been provided.
 */
public class GlobalPlatformCommandSet {
  static final byte INS_SELECT = (byte) 0xA4;
  static final byte INS_INITIALIZE_UPDATE = (byte) 0x50;
  static final byte INS_EXTERNAL_AUTHENTICATE = (byte) 0x82;
  static final byte INS_DELETE = (byte) 0xE4;
  static final byte INS_INSTALL = (byte) 0xE6;
  static final byte INS_LOAD = (byte) 0xE8;
  static final byte INS_PUT_KEY = (byte) 0xD8;

  static final byte SELECT_P1_BY_NAME = (byte) 0x04;
  static final byte EXTERNAL_AUTHENTICATE_P1 = (byte) 0x01;
  static final byte INSTALL_FOR_LOAD_P1 = (byte) 0x02;
  static final byte INSTALL_FOR_INSTALL_P1 = (byte) 0x0C;
  static final byte LOAD_P1_MORE_BLOCKS = (byte) 0x00;
  static final byte LOAD_P1_LAST_BLOCK = (byte) 0x80;

  private final CardChannel apduChannel;
  private SecureChannel secureChannel;
  private SCP02Keys cardKeys;
  private Session session;

  private final byte[] testKey = Hex.decode("404142434445464748494a4b4c4d4e4f");

  /**
   * Constructs a new command set with the given CardChannel.
   *
   * @param apduChannel the channel to the card
   */
  public GlobalPlatformCommandSet(CardChannel apduChannel) {
    this.apduChannel = apduChannel;
    this.cardKeys = new SCP02Keys(testKey, testKey, testKey);
  }

  /**
   * Selects the ISD of the card.
   *
   * @return the card response
   *
   * @throws IOException communication error
   */
  public APDUResponse select() throws IOException {
    APDUCommand cmd = new APDUCommand(0x00, INS_SELECT, SELECT_P1_BY_NAME, 0, new byte[0]);
    return apduChannel.send(cmd);
  }

  /**
   * Sends an INITIALIZE UPDATE command. Use the openSecureChannel method instead of calling this directly, unless you
   * need to use a specific host challenge.
   *
   * @param hostChallenge the host challenge.
   * @return the card response
   *
   * @throws IOException communication error
   */
  public APDUResponse initializeUpdate(byte[] hostChallenge) throws IOException, APDUException {
    APDUCommand cmd = new APDUCommand(0x80, INS_INITIALIZE_UPDATE, 0, 0, hostChallenge, true);
    APDUResponse resp = apduChannel.send(cmd);
    if (resp.isOK()) {
      this.session = SecureChannel.verifyChallenge(hostChallenge, this.cardKeys, resp);
      this.secureChannel = new SecureChannel(this.apduChannel, this.session.getKeys());
    }

    return resp;
  }

  /**
   * Sends an EXTERNAL AUTHENTICATE command. Use the openSecureChannel method instead of calling this directly, unless you
   * need to use a specific host challenge.
   *
   * @param hostChallenge the host challenge.
   * @return the card response
   *
   * @throws IOException communication error
   */
  public APDUResponse externalAuthenticate(byte[] hostChallenge) throws IOException {
    byte[] cardChallenge = this.session.getCardChallenge();
    byte[] data = new byte[cardChallenge.length + hostChallenge.length];
    System.arraycopy(cardChallenge, 0, data, 0, cardChallenge.length);
    System.arraycopy(hostChallenge, 0, data, cardChallenge.length, hostChallenge.length);

    byte[] paddedData = Crypto.appendDESPadding(data);
    byte[] hostCryptogram = Crypto.mac3des(this.session.getKeys().encKeyData, paddedData, Crypto.NullBytes8);

    APDUCommand cmd = new APDUCommand(0x84, INS_EXTERNAL_AUTHENTICATE, EXTERNAL_AUTHENTICATE_P1, 0, hostCryptogram);
    return this.secureChannel.send(cmd);
  }

  /**
   * Opens an SCP02 secure channel with default keys.
   *
   * @throws APDUException the card didn't respond 0x9000 to either INITIALIZE UPDATE or EXTERNAL AUTHENTICATE
   * @throws IOException communication error
   */
  public void openSecureChannel() throws APDUException, IOException {
    SecureRandom random = new SecureRandom();
    byte[] hostChallenge = new byte[8];
    random.nextBytes(hostChallenge);
    initializeUpdate(hostChallenge).checkOK();
    externalAuthenticate(hostChallenge).checkOK();
  }

  /**
   * Sends a PUT KEY APDU to load or replace SCP02 keys. The keys are assumed to be 3DES keys
   *
   * @param encKey the ENC key to load
   * @param macKey the MAC key to load
   * @param dekKey the DEK key to load
   * @param oldKvn the KVN to replace, 0 to put a new key without replacing
   * @param newKvn the KVN of the new keyset
   * @return
   * @throws IOException
   */
  public APDUResponse putSCP02Keys(byte[] encKey, byte[] macKey, byte[] dekKey, int oldKvn, int newKvn) throws IOException {
    if (encKey.length != 16 || macKey.length != 16 || dekKey.length != 16){
      throw new IllegalArgumentException("All keys must be 16-byte 3DES keys");
    }

    ByteArrayOutputStream bos = new ByteArrayOutputStream();
    bos.write(newKvn);
    writeSCP02Key(bos, encKey);
    writeSCP02Key(bos, macKey);
    writeSCP02Key(bos, dekKey);

    APDUCommand cmd = new APDUCommand(0x84, INS_PUT_KEY, oldKvn, 0x80, bos.toByteArray());
    return this.secureChannel.send(cmd);
  }

  /**
   * writes an encrypted key for the PUT KEY command
   * @param bos the output stream to write to
   * @param key the key to encrypt and write
   * @throws IOException if the ByteArrayOutputStream throws it (never)
   */
  private void writeSCP02Key(ByteArrayOutputStream bos, byte[] key) throws IOException {
    byte[] encrypted = Crypto.ecb3des(session.getKeys().getDekKeyData(), key);
    byte[] kcv = Crypto.kcv3des(key);

    bos.write(0x80);
    bos.write(encrypted.length);
    bos.write(encrypted);
    bos.write(kcv.length);
    bos.write(kcv);
  }

  /**
   * Deletes the Keycard applet instance.
   *
   * @return the card response
   * @throws IOException communication error
   */
  public APDUResponse deleteKeycardInstance() throws IOException {
    return delete(Identifiers.getKeycardInstanceAID());
  }

  /**
   * Deletes the NDEF applet instance.
   *
   * @return the card response
   * @throws IOException communication error
   */
  public APDUResponse deleteNDEFInstance() throws IOException {
    return delete(Identifiers.NDEF_INSTANCE_AID);
  }

  /**
   * Deletes the Keycard package.
   *
   * @return the card response
   * @throws IOException communication error
   */
  public APDUResponse deleteKeycardPackage() throws IOException {
    return delete(Identifiers.PACKAGE_AID);
  }

  /**
   * Deletes the Keycard package and all applets installed from it. This is the method to use to remove a Keycard
   * installation.
   *
   * @throws APDUException one of the DELETE commands failed
   * @throws IOException communication error
   */
  public void deleteKeycardInstancesAndPackage() throws IOException, APDUException {
    deleteNDEFInstance().checkSW(APDUResponse.SW_OK, APDUResponse.SW_REFERENCED_DATA_NOT_FOUND);
    deleteKeycardInstance().checkSW(APDUResponse.SW_OK, APDUResponse.SW_REFERENCED_DATA_NOT_FOUND);
    deleteKeycardPackage().checkSW(APDUResponse.SW_OK, APDUResponse.SW_REFERENCED_DATA_NOT_FOUND);
  }

  /**
   * Sends a DELETE APDU with the given AID
   * @param aid the AID to the delete
   * @return the raw card response
   *
   * @throws IOException communication error.
   */
  public APDUResponse delete(byte[] aid) throws IOException {
    byte[] data = new byte[aid.length + 2];
    data[0] = 0x4F;
    data[1] = (byte) aid.length;
    System.arraycopy(aid, 0, data, 2, aid.length);

    APDUCommand cmd = new APDUCommand(0x80, INS_DELETE, 0, 0, data);

    return this.secureChannel.send(cmd);
  }

  /**
   * Loads the Keycard package.
   *
   * @param in the CAP file as an InputStream
   * @param cb the progress callback
   *
   * @throws IOException communication error
   * @throws APDUException one of the INSTALL [for Load] or LOAD commands failed
   */
  public void loadKeycardPackage(InputStream in, LoadCallback cb) throws IOException, APDUException {
    installForLoad(Identifiers.PACKAGE_AID).checkOK();

    Load load = new Load(in);

    byte[] block;
    int steps = load.blocksCount();

    while((block = load.nextDataBlock()) != null) {
      load(block, (load.getCount() - 1), load.hasMore()).checkOK();
      cb.blockLoaded(load.getCount(), steps);
    }
  }

  /**
   * Sends an INSTALL [for LOAD] APDU. Use only if loading something other than the Keycard package.
   *
   * @param aid the AID
   *
   * @return the card response
   * @throws IOException communication error
   */
  public APDUResponse installForLoad(byte[] aid) throws IOException {
    return installForLoad(aid, new byte[0]);
  }

  /**
   * Sends an INSTALL [for LOAD] APDU with package extradition. Use only if loading something other than the Keycard package.
   *
   * @param aid the AID
   * @param sdaid the AID of the SD target of the extradition
   *
   * @return the card response
   * @throws IOException communication error
   */
  public APDUResponse installForLoad(byte[] aid, byte[] sdaid) throws IOException {
    ByteArrayOutputStream data = new ByteArrayOutputStream();
    data.write(aid.length);
    data.write(aid);
    data.write(sdaid.length);
    data.write(sdaid);

    // empty hash length and hash
    data.write(0x00);
    data.write(0x00);
    data.write(0x00);

    APDUCommand cmd = new APDUCommand(0x80, INS_INSTALL, INSTALL_FOR_LOAD_P1, 0, data.toByteArray());

    return this.secureChannel.send(cmd);
  }

  /**
   * Sends a single LOAD APDU. Use only if loading something other than the Keycard package.
   *
   * @param data the data of the block
   * @param count the block number
   * @param hasMoreBlocks whether there are more blocks coming or not
   * @return the card response
   * @throws IOException communication error
   */
  public APDUResponse load(byte[] data, int count, boolean hasMoreBlocks) throws IOException {
    int p1 = hasMoreBlocks ? LOAD_P1_MORE_BLOCKS : LOAD_P1_LAST_BLOCK;
    APDUCommand cmd = new APDUCommand(0x80, INS_LOAD, p1, count, data);
    return this.secureChannel.send(cmd);
  }

  /**
   * Sends an INSTALL [for Install & Make Selectable] command. Use only if not installing applets part of the Keycard
   * package
   *
   * @param packageAID the package AID
   * @param appletAID the applet AID
   * @param instanceAID the instance AID
   * @param params the installation parameters
   * @return the card response
   * @throws IOException communication error
   */
  public APDUResponse installForInstall(byte[] packageAID, byte[] appletAID, byte[] instanceAID, byte[] params) throws IOException {
    ByteArrayOutputStream data = new ByteArrayOutputStream();
    data.write(packageAID.length);
    data.write(packageAID);
    data.write(appletAID.length);
    data.write(appletAID);
    data.write(instanceAID.length);
    data.write(instanceAID);

    byte[] privileges = new byte[]{0x00};
    data.write(privileges.length);
    data.write(privileges);

    byte[] fullParams = new byte[2 + params.length];
    fullParams[0] = (byte) 0xC9;
    fullParams[1] = (byte) params.length;
    System.arraycopy(params, 0, fullParams, 2, params.length);

    data.write(fullParams.length);
    data.write(fullParams);

    // empty perform token
    data.write(0x00);
    APDUCommand cmd = new APDUCommand(0x80, INS_INSTALL, INSTALL_FOR_INSTALL_P1, 0, data.toByteArray());

    return this.secureChannel.send(cmd);
  }

  /**
   * Installs the NDEF applet from the Keycard package.
   *
   * @param ndefRecord the initial NDEF record. Can be a zero-length array but not null
   * @return the card response
   * @throws IOException communication error
   */
  public APDUResponse installNDEFApplet(byte[] ndefRecord) throws IOException {
    return installForInstall(Identifiers.PACKAGE_AID, Identifiers.NDEF_AID, Identifiers.NDEF_INSTANCE_AID, ndefRecord);
  }

  /**
   * Installs the Keycard applet.
   *
   * @return the card response
   * @throws IOException communication error.
   */
  public APDUResponse installKeycardApplet() throws IOException {
    return installForInstall(Identifiers.PACKAGE_AID, Identifiers.KEYCARD_AID, Identifiers.getKeycardInstanceAID(), new byte[0]);
  }
}
