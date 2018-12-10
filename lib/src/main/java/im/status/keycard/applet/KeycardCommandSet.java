package im.status.keycard.applet;

import im.status.keycard.io.APDUCommand;
import im.status.keycard.io.APDUException;
import im.status.keycard.io.APDUResponse;
import im.status.keycard.io.CardChannel;
import org.spongycastle.jce.interfaces.ECPrivateKey;
import org.spongycastle.jce.interfaces.ECPublicKey;
import org.spongycastle.util.encoders.Hex;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.IOException;
import java.security.KeyPair;
import java.util.Arrays;

/**
 * This class is used to send APDU to the applet. Each method corresponds to an APDU as defined in the APPLICATION.md
 * file. Some APDUs map to multiple methods for the sake of convenience since their payload or response require some
 * pre/post processing.
 */
public class KeycardCommandSet {
  static final byte INS_INIT = (byte) 0xFE;
  static final byte INS_GET_STATUS = (byte) 0xF2;
  static final byte INS_SET_NDEF = (byte) 0xF3;
  static final byte INS_VERIFY_PIN = (byte) 0x20;
  static final byte INS_CHANGE_PIN = (byte) 0x21;
  static final byte INS_UNBLOCK_PIN = (byte) 0x22;
  static final byte INS_LOAD_KEY = (byte) 0xD0;
  static final byte INS_DERIVE_KEY = (byte) 0xD1;
  static final byte INS_GENERATE_MNEMONIC = (byte) 0xD2;
  static final byte INS_REMOVE_KEY = (byte) 0xD3;
  static final byte INS_GENERATE_KEY = (byte) 0xD4;
  static final byte INS_DUPLICATE_KEY = (byte) 0xD5;
  static final byte INS_SIGN = (byte) 0xC0;
  static final byte INS_SET_PINLESS_PATH = (byte) 0xC1;
  static final byte INS_EXPORT_KEY = (byte) 0xC2;

  public static final byte GET_STATUS_P1_APPLICATION = 0x00;
  public static final byte GET_STATUS_P1_KEY_PATH = 0x01;

  public static final byte LOAD_KEY_P1_EC = 0x01;
  public static final byte LOAD_KEY_P1_EXT_EC = 0x02;
  public static final byte LOAD_KEY_P1_SEED = 0x03;

  public static final byte DERIVE_P1_SOURCE_MASTER = (byte) 0x00;
  public static final byte DERIVE_P1_SOURCE_PARENT = (byte) 0x40;
  public static final byte DERIVE_P1_SOURCE_CURRENT = (byte) 0x80;

  static final byte DUPLICATE_KEY_P1_START = 0x00;
  static final byte DUPLICATE_KEY_P1_ADD_ENTROPY = 0x01;
  static final byte DUPLICATE_KEY_P1_EXPORT = 0x02;
  static final byte DUPLICATE_KEY_P1_IMPORT = 0x03;

  public static final int GENERATE_MNEMONIC_12_WORDS = 0x04;
  public static final int GENERATE_MNEMONIC_15_WORDS = 0x05;
  public static final int GENERATE_MNEMONIC_18_WORDS = 0x06;
  public static final int GENERATE_MNEMONIC_21_WORDS = 0x07;
  public static final int GENERATE_MNEMONIC_24_WORDS = 0x08;

  static final byte EXPORT_KEY_P1_CURRENT = 0x00;
  static final byte EXPORT_KEY_P1_DERIVE = 0x01;
  static final byte EXPORT_KEY_P1_DERIVE_AND_MAKE_CURRENT = 0x02;

  static final byte EXPORT_KEY_P2_PRIVATE_AND_PUBLIC = 0x00;
  static final byte EXPORT_KEY_P2_PUBLIC_ONLY = 0x01;

  static final byte TLV_APPLICATION_INFO_TEMPLATE = (byte) 0xA4;

  private final CardChannel apduChannel;
  private SecureChannelSession secureChannel;

  public KeycardCommandSet(CardChannel apduChannel) {
    this.apduChannel = apduChannel;
    this.secureChannel = new SecureChannelSession();
  }

  protected void setSecureChannel(SecureChannelSession secureChannel) {
    this.secureChannel = secureChannel;
  }

  /**
   * Returns the current pairing data.
   */
  public Pairing getPairing() {
    return secureChannel.getPairing();
  }

  /**
   * Sets the pairing data.
   * @param pairing data from an existing pairing
   */
  public void setPairing(Pairing pairing) {
    secureChannel.setPairing(pairing);
  }

  /**
   * Selects the applet. The applet is assumed to have been installed with its default AID. The returned data is a
   * public key which must be used to initialize the secure channel.
   *
   * @return the raw card response
   * @throws IOException communication error
   */
  public APDUResponse select() throws IOException {
    APDUCommand selectApplet = new APDUCommand(0x00, 0xA4, 4, 0, Identifiers.getKeycardInstanceAID());
    APDUResponse resp =  apduChannel.send(selectApplet);

    if (resp.getSw() == 0x9000) {
      this.secureChannel.generateSecret(extractPublicKeyFromSelect(resp.getData()));
      this.secureChannel.reset();
    }

    return resp;
  }

  /**
   * Opens the secure channel. Calls the corresponding method of the SecureChannel class.
   *
   * @throws IOException communication error
   */
  public void autoOpenSecureChannel() throws IOException {
    secureChannel.autoOpenSecureChannel(apduChannel);
  }

  /**
   * Automatically pairs. Derives the secret from the given password.
   *
   * @throws IOException communication error
   */
  public void autoPair(String pairingPassword) throws IOException {
    byte[] secret = pairingPasswordToSecret(pairingPassword);

    secureChannel.autoPair(apduChannel, secret);
  }

  /**
   * Converts a pairing password to a binary pairing secret.
   *
   * @param pairingPassword the pairing password
   * @return the pairing secret
   */
  public byte[] pairingPasswordToSecret(String pairingPassword) {
    SecretKey key;

    try {
      SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
      PBEKeySpec spec = new PBEKeySpec(pairingPassword.toCharArray(), "Keycard Pairing Password Salt".getBytes(), 50000, 32 * 8);
      key = skf.generateSecret(spec);
    } catch (Exception e) {
      throw new RuntimeException("Is Bouncycastle correctly initialized?");
    }
    return key.getEncoded();
  }

  /**
   * Automatically pairs. Calls the corresponding method of the SecureChannel class.
   *
   * @throws IOException communication error
   */
  public void autoPair(byte[] sharedSecret) throws IOException {
    secureChannel.autoPair(apduChannel, sharedSecret);
  }

  /**
   * Automatically unpairs. Calls the corresponding method of the SecureChannel class.
   *
   * @throws IOException communication error
   */
  public void autoUnpair() throws IOException {
    secureChannel.autoUnpair(apduChannel);
  }

  /**
   * Sends a OPEN SECURE CHANNEL APDU. Calls the corresponding method of the SecureChannel class.
   */
  public APDUResponse openSecureChannel(byte index, byte[] data) throws IOException {
    return secureChannel.openSecureChannel(apduChannel, index, data);
  }

  /**
   * Sends a MUTUALLY AUTHENTICATE APDU. Calls the corresponding method of the SecureChannel class.
   */
  public APDUResponse mutuallyAuthenticate() throws IOException {
    return secureChannel.mutuallyAuthenticate(apduChannel);
  }

  /**
   * Sends a MUTUALLY AUTHENTICATE APDU. Calls the corresponding method of the SecureChannel class.
   */
  public APDUResponse mutuallyAuthenticate(byte[] data) throws IOException {
    return secureChannel.mutuallyAuthenticate(apduChannel, data);
  }

  /**
   * Sends a PAIR APDU. Calls the corresponding method of the SecureChannel class.
   */
  public APDUResponse pair(byte p1, byte[] data) throws IOException {
    return secureChannel.pair(apduChannel, p1, data);
  }

  /**
   * Sends a UNPAIR APDU. Calls the corresponding method of the SecureChannel class.
   */
  public APDUResponse unpair(byte p1) throws IOException {
    return secureChannel.unpair(apduChannel, p1);
  }

  /**
   * Unpair all other clients.
   */
  public void unpairOthers() throws IOException, APDUException {
    secureChannel.unpairOthers(apduChannel);
  }

  /**
   * Sends a GET STATUS APDU. The info byte is the P1 parameter of the command, valid constants are defined in the applet
   * class itself.
   *
   * @param info the P1 of the APDU
   * @return the raw card response
   * @throws IOException communication error
   */
  public APDUResponse getStatus(byte info) throws IOException {
    APDUCommand getStatus = secureChannel.protectedCommand(0x80, INS_GET_STATUS, info, 0, new byte[0]);
    return secureChannel.transmit(apduChannel, getStatus);
  }

  /**
   * Sends a SET NDEF APDU.
   *
   * @param ndef the data field of the APDU
   * @return the raw card response
   * @throws IOException communication error
   */
  public APDUResponse setNDEF(byte[] ndef) throws IOException {
    APDUCommand setNDEF = secureChannel.protectedCommand(0x80, INS_SET_NDEF, 0, 0, ndef);
    return secureChannel.transmit(apduChannel, setNDEF);
  }

  /**
   * Sends a VERIFY PIN APDU. The raw bytes of the given string are encrypted using the secure channel and used as APDU
   * data.
   *
   * @param pin the pin
   * @return the raw card response
   * @throws IOException communication error
   */
  public APDUResponse verifyPIN(String pin) throws IOException {
    APDUCommand verifyPIN = secureChannel.protectedCommand(0x80, INS_VERIFY_PIN, 0, 0, pin.getBytes());
    return secureChannel.transmit(apduChannel, verifyPIN);
  }

  /**
   * Sends a CHANGE PIN APDU. The raw bytes of the given string are encrypted using the secure channel and used as APDU
   * data.
   *
   * @param pinType the PIN type
   * @param pin the new PIN
   * @return the raw card response
   * @throws IOException communication error
   */
  public APDUResponse changePIN(int pinType, String pin) throws IOException {
    return changePIN(pinType, pin.getBytes());
  }

  /**
   * Sends a CHANGE PIN APDU. The raw bytes of the given string are encrypted using the secure channel and used as APDU
   * data.
   *
   * @param pinType the PIN type
   * @param pin the new PIN
   * @return the raw card response
   * @throws IOException communication error
   */
  public APDUResponse changePIN(int pinType, byte[] pin) throws IOException {
    APDUCommand changePIN = secureChannel.protectedCommand(0x80, INS_CHANGE_PIN, pinType, 0, pin);
    return secureChannel.transmit(apduChannel, changePIN);
  }

  /**
   * Sends an UNBLOCK PIN APDU. The PUK and PIN are concatenated and the raw bytes are encrypted using the secure
   * channel and used as APDU data.
   *
   * @return the raw card response
   * @throws IOException communication error
   */
  public APDUResponse unblockPIN(String puk, String newPin) throws IOException {
    APDUCommand unblockPIN = secureChannel.protectedCommand(0x80, INS_UNBLOCK_PIN, 0, 0, (puk + newPin).getBytes());
    return secureChannel.transmit(apduChannel, unblockPIN);
  }

  /**
   * Sends a LOAD KEY APDU. The given seed is sent as-is and the P1 of the command is set to LOAD_KEY_P1_SEED (0x03).
   * This works on cards which support public key derivation. The loaded keyset is extended and support further
   * key derivation.
   *
   * @param seed the binary seed
   * @return the raw card response
   * @throws IOException communication error
   */
  public APDUResponse loadKey(byte[] seed) throws IOException {
    return loadKey(seed, LOAD_KEY_P1_SEED);
  }

  /**
   * Sends a LOAD KEY APDU. The key is sent in TLV format, includes the public key and no chain code, meaning that
   * the card will not be able to do further key derivation.
   *
   * @param ecKeyPair a key pair
   * @return the raw card response
   * @throws IOException communication error
   */
  public APDUResponse loadKey(KeyPair ecKeyPair) throws IOException {
    return loadKey(ecKeyPair, false, null);
  }

  /**
   * Sends a LOAD KEY APDU. The key is sent in TLV format. The public key is included or not depending on the value
   * of the omitPublicKey parameter. The chain code is included if the chainCode is not null. P1 is set automatically
   * to either LOAD_KEY_P1_EC or LOAD_KEY_P1_EXT_EC depending on the presence of the chainCode.
   *
   * @param keyPair a key pair
   * @param omitPublicKey whether the public key is sent or not
   * @param chainCode the chain code
   * @return the raw card response
   * @throws IOException communication error
   */
  public APDUResponse loadKey(KeyPair keyPair, boolean omitPublicKey, byte[] chainCode) throws IOException {
    byte[] publicKey = ((ECPublicKey) keyPair.getPublic()).getQ().getEncoded(false);
    byte[] privateKey = ((ECPrivateKey) keyPair.getPrivate()).getD().toByteArray();

    return loadKey(new BIP32KeyPair(privateKey, chainCode, publicKey), omitPublicKey);
  }

  /**
   * Sends a LOAD KEY APDU. The key is sent in TLV format. The public key is included if not null. The chain code is
   * included if not null. P1 is set automatically to either LOAD_KEY_P1_EC or
   * LOAD_KEY_P1_EXT_EC depending on the presence of the chainCode.
   *
   * @param publicKey a raw public key
   * @param privateKey a raw private key
   * @param chainCode the chain code
   * @return the raw card response
   * @throws IOException communication error
   */
  public APDUResponse loadKey(byte[] publicKey, byte[] privateKey, byte[] chainCode) throws IOException {
    return loadKey(new BIP32KeyPair(privateKey, chainCode, publicKey), publicKey == null);
  }

  public APDUResponse loadKey(BIP32KeyPair keyPair) throws IOException {
    return loadKey(keyPair, false);
  }

  public APDUResponse loadKey(BIP32KeyPair keyPair, boolean omitPublic)  throws IOException {
    byte p1;

    if (keyPair.isExtended()) {
      p1 = LOAD_KEY_P1_EXT_EC;
    } else {
      p1 = LOAD_KEY_P1_EC;
    }

    return loadKey(keyPair.toTLV(!omitPublic), p1);
  }

  /**
   * Sends a LOAD KEY APDU. The data is encrypted and sent as-is. The keyType parameter is used as P1.
   *
   * @param data key data
   * @param keyType the P1 parameter
   * @return the raw card response
   * @throws IOException communication error
   */
  public APDUResponse loadKey(byte[] data, byte keyType) throws IOException {
    APDUCommand loadKey = secureChannel.protectedCommand(0x80, INS_LOAD_KEY, keyType, 0, data);
    return secureChannel.transmit(apduChannel, loadKey);
  }

  /**
   * Sends a GENERATE MNEMONIC APDU. The cs parameter is the length of the checksum and is used as P1.
   *
   * @param cs the P1 parameter
   * @return the raw card response
   * @throws IOException communication error
   */
  public APDUResponse generateMnemonic(int cs) throws IOException {
    APDUCommand generateMnemonic = secureChannel.protectedCommand(0x80, INS_GENERATE_MNEMONIC, cs, 0, new byte[0]);
    return secureChannel.transmit(apduChannel, generateMnemonic);
  }

  /**
   * Sends a REMOVE KEY APDU.
   *
   * @return the raw card response
   * @throws IOException communication error
   */
  public APDUResponse removeKey() throws IOException {
    APDUCommand removeKey = secureChannel.protectedCommand(0x80, INS_REMOVE_KEY, 0, 0, new byte[0]);
    return secureChannel.transmit(apduChannel, removeKey);
  }

  /**
   * Sends a GENERATE KEY APDU.
   *
   * @return the raw card response
   * @throws IOException communication error
   */
  public APDUResponse generateKey() throws IOException {
    APDUCommand generateKey = secureChannel.protectedCommand(0x80, INS_GENERATE_KEY, 0, 0, new byte[0]);
    return secureChannel.transmit(apduChannel, generateKey);
  }

  /**
   * Sends a DUPLICATE KEY APDU. The P1 is set to 00, P2 to the entropy count and the data is the first entropy piece.
   * This starts a duplication session. Requires an open Secure Channel and authenticated PIN.
   *
   * @param entropyCount the number of entropy pieces to expect, including the one in this APDU
   * @param firstEntropy a random 32-byte number
   * @return the raw card response
   * @throws IOException communication error
   */
  public APDUResponse duplicateKeyStart(int entropyCount, byte[] firstEntropy) throws IOException {
    APDUCommand duplicateKeyStart = secureChannel.protectedCommand(0x80, INS_DUPLICATE_KEY, DUPLICATE_KEY_P1_START, entropyCount, firstEntropy);
    return secureChannel.transmit(apduChannel, duplicateKeyStart);
  }

  /**
   * Sends a DUPLICATE KEY APDU. The P1 is set to 01 and the data is the entropy. This adds entropy and does not require
   * a Secure Channel or authenticated PIN.
   *
   * @param entropy a random 32-byte number
   * @return the raw card response
   * @throws IOException communication error
   */
  public APDUResponse duplicateKeyAddEntropy(byte[] entropy) throws IOException {
    APDUCommand duplicateKeyAddEntropy = new APDUCommand(0x80, INS_DUPLICATE_KEY, DUPLICATE_KEY_P1_ADD_ENTROPY, 0, secureChannel.oneShotEncrypt(entropy));
    return apduChannel.send(duplicateKeyAddEntropy);
  }

  /**
   * Sends a DUPLICATE KEY APDU. The P1 is set to 02. This exports the encrypted master key including chaining code.
   *
   * @return the raw card response
   * @throws IOException communication error
   */
  public APDUResponse duplicateKeyExport() throws IOException {
    APDUCommand duplicateKeyExport = secureChannel.protectedCommand(0x80, INS_DUPLICATE_KEY, DUPLICATE_KEY_P1_EXPORT, 0, new byte[0]);
    return secureChannel.transmit(apduChannel, duplicateKeyExport);
  }

  /**
   * Sends a DUPLICATE KEY APDU. The P1 is set to 03. This imports an encrypted master key including chaining code. The
   * response data contains the key UID of the imported key.
   *
   * @param key the key, exported from another card in the same duplication session.
   * @return the raw card response
   * @throws IOException communication error
   */
  public APDUResponse duplicateKeyImport(byte[] key) throws IOException {
    APDUCommand duplicateKeyImport = secureChannel.protectedCommand(0x80, INS_DUPLICATE_KEY, DUPLICATE_KEY_P1_IMPORT, 0, key);
    return secureChannel.transmit(apduChannel, duplicateKeyImport);
  }

  /**
   * Sends a SIGN APDU. This signs a precomputed hash so the input must be exactly 32-bytes long.
   *
   * @param data the data to sign
   * @return the raw card response
   * @throws IOException communication error
   */
  public APDUResponse sign(byte[] data) throws IOException {
    APDUCommand sign = secureChannel.protectedCommand(0x80, INS_SIGN, 0x00, 0x00, data);
    return secureChannel.transmit(apduChannel, sign);
  }

  /**
   * Sends a DERIVE KEY APDU with the given key path.
   *
   * @param keypath the string key path
   * @return the raw card response
   * @throws IOException communication error
   */
  public APDUResponse deriveKey(String keypath) throws IOException {
    KeyPath path = new KeyPath(keypath);
    return deriveKey(path.getData(), path.getSource());
  }

  /**
   * Sends a DERIVE KEY APDU. The data is encrypted and sent as-is. The P1 is forced to 0, meaning that the derivation
   * starts from the master key.
   *
   * @param data the raw key path
   * @return the raw card response
   * @throws IOException communication error
   */
  public APDUResponse deriveKey(byte[] data) throws IOException {
    return deriveKey(data, DERIVE_P1_SOURCE_MASTER);
  }

  /**
   * Sends a DERIVE KEY APDU. The data is encrypted and sent as-is. The source parameter is used as P1.
   *
   * @param data the raw key path or a public key
   * @param source the source to start derivation
   * @return the raw card response
   * @throws IOException communication error
   */
  public APDUResponse deriveKey(byte[] data, int source) throws IOException {
    APDUCommand deriveKey = secureChannel.protectedCommand(0x80, INS_DERIVE_KEY, source, 0x00, data);
    return secureChannel.transmit(apduChannel, deriveKey);
  }

  /**
   * Sends a SET PINLESS PATH APDU. The data is encrypted and sent as-is.
   *
   * @param data the raw key path
   * @return the raw card response
   * @throws IOException communication error
   */
  public APDUResponse setPinlessPath(byte [] data) throws IOException {
    APDUCommand setPinlessPath = secureChannel.protectedCommand(0x80, INS_SET_PINLESS_PATH, 0x00, 0x00, data);
    return secureChannel.transmit(apduChannel, setPinlessPath);
  }

  /**
   * Sends an EXPORT KEY APDU to export the current key.
   *
   * @param publicOnly exports only the public key
   * @return the raw card reponse
   * @throws IOException communication error
   */
  public APDUResponse exportCurrentKey(boolean publicOnly) throws IOException {
    return exportKey(EXPORT_KEY_P1_CURRENT, publicOnly, new byte[0]);
  }

  /**
   * Sends an EXPORT KEY APDU. Performs derivation of the given keypath and optionally makes it the current key.
   *
   * @param keyPath the keypath to export
   * @param makeCurrent if the key should be made current or not
   * @param publicOnly the P2 parameter
   * @return the raw card response
   * @throws IOException communication error
   */
  public APDUResponse exportKey(String keyPath, boolean makeCurrent, boolean publicOnly) throws IOException {
    KeyPath path = new KeyPath(keyPath);
    return exportKey(path.getData(), path.getSource(), makeCurrent, publicOnly);
  }

  /**
   * Sends an EXPORT KEY APDU. Performs derivation of the given keypath and optionally makes it the current key.
   *
   * @param keyPath the keypath to export
   * @param makeCurrent if the key should be made current or not
   * @param publicOnly the P2 parameter
   * @return the raw card response
   * @throws IOException communication error
   */
  public APDUResponse exportKey(byte[] keyPath, int source, boolean makeCurrent, boolean publicOnly) throws IOException {
    int p1 = source | (makeCurrent ? EXPORT_KEY_P1_DERIVE_AND_MAKE_CURRENT : EXPORT_KEY_P1_DERIVE);
    return exportKey(p1, publicOnly, keyPath);
  }

  /**
   * Sends an EXPORT KEY APDU. The parameters are sent as-is.
   *
   * @param derivationOptions the P1 parameter
   * @param publicOnly the P2 parameter
   * @param keypath the data parameter
   * @return the raw card response
   * @throws IOException communication error
   */
  public APDUResponse exportKey(int derivationOptions, boolean publicOnly, byte[] keypath) throws IOException {
    byte p2 = publicOnly ? EXPORT_KEY_P2_PUBLIC_ONLY : EXPORT_KEY_P2_PRIVATE_AND_PUBLIC;
    APDUCommand exportKey = secureChannel.protectedCommand(0x80, INS_EXPORT_KEY, derivationOptions, p2, keypath);
    return secureChannel.transmit(apduChannel, exportKey);
  }

  /**
   * Sends the INIT command to the card.
   *
   * @param pin the PIN
   * @param puk the PUK
   * @param pairingPassword pairing password
   * @return the raw card response
   * @throws IOException communication error
   */
  public APDUResponse init(String pin, String puk, String pairingPassword) throws IOException {
    return this.init(pin, puk, pairingPasswordToSecret(pairingPassword));
  }

  /**
   * Sends the INIT command to the card.
   *
   * @param pin the PIN
   * @param puk the PUK
   * @param sharedSecret the shared secret for pairing
   * @return the raw card response
   * @throws IOException communication error
   */
  public APDUResponse init(String pin, String puk, byte[] sharedSecret) throws IOException {
    byte[] initData = Arrays.copyOf(pin.getBytes(), pin.length() + puk.length() + sharedSecret.length);
    System.arraycopy(puk.getBytes(), 0, initData, pin.length(), puk.length());
    System.arraycopy(sharedSecret, 0, initData, pin.length() + puk.length(), sharedSecret.length);
    APDUCommand init = new APDUCommand(0x80, INS_INIT, 0, 0, secureChannel.oneShotEncrypt(initData));
    return apduChannel.send(init);
  }

  private byte[] extractPublicKeyFromSelect(byte[] select) {
    return new ApplicationInfo(select).getSecureChannelPubKey();
  }
}
