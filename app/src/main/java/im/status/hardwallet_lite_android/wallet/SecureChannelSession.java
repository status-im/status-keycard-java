package im.status.hardwallet_lite_android.wallet;

import im.status.hardwallet_lite_android.io.APDUCommand;
import im.status.hardwallet_lite_android.io.APDUException;
import im.status.hardwallet_lite_android.io.APDUResponse;
import im.status.hardwallet_lite_android.io.CardChannel;
import org.spongycastle.crypto.engines.AESEngine;
import org.spongycastle.crypto.macs.CBCBlockCipherMac;
import org.spongycastle.crypto.params.KeyParameter;
import org.spongycastle.jce.ECNamedCurveTable;
import org.spongycastle.jce.interfaces.ECPublicKey;
import org.spongycastle.jce.spec.ECParameterSpec;
import org.spongycastle.jce.spec.ECPublicKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.*;
import java.util.Arrays;

/**
 * Handles a SecureChannel session with the card.
 */
public class SecureChannelSession {
  public static final short SC_SECRET_LENGTH = 32;
  public static final short SC_BLOCK_SIZE = 16;

  public static final byte INS_OPEN_SECURE_CHANNEL = 0x10;
  public static final byte INS_MUTUALLY_AUTHENTICATE = 0x11;
  public static final byte INS_PAIR = 0x12;
  public static final byte INS_UNPAIR = 0x13;

  public static final byte PAIR_P1_FIRST_STEP = 0x00;
  public static final byte PAIR_P1_LAST_STEP = 0x01;
  
  public static final int PAYLOAD_MAX_SIZE = 223;

  static final byte PAIRING_MAX_CLIENT_COUNT = 5;


  private byte[] secret;
  private byte[] publicKey;
  private byte[] pairingKey;
  private byte[] iv;
  private byte pairingIndex;
  private Cipher sessionCipher;
  private CBCBlockCipherMac sessionMac;
  private SecretKeySpec sessionEncKey;
  private KeyParameter sessionMacKey;
  private SecureRandom random;
  private boolean open;

  /**
   * Constructs a SecureChannel session on the client. The client should generate a fresh key pair for each session.
   * The public key of the card is used as input for the EC-DH algorithm. The output is stored as the secret.
   *
   * @param keyData the public key returned by the applet as response to the SELECT command
   */
  public SecureChannelSession(byte[] keyData) {
      random = new SecureRandom();
      generateSecret(keyData);
      open = false;
  }

  public void generateSecret(byte[] keyData) {
    try {
      random = new SecureRandom();
      ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256k1");
      KeyPairGenerator g = KeyPairGenerator.getInstance("ECDH");
      g.initialize(ecSpec, random);

      KeyPair keyPair = g.generateKeyPair();

      publicKey = ((ECPublicKey) keyPair.getPublic()).getQ().getEncoded(false);
      KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
      keyAgreement.init(keyPair.getPrivate());

      ECPublicKeySpec cardKeySpec = new ECPublicKeySpec(ecSpec.getCurve().decodePoint(keyData), ecSpec);
      ECPublicKey cardKey = (ECPublicKey) KeyFactory.getInstance("ECDSA").generatePublic(cardKeySpec);

      keyAgreement.doPhase(cardKey, true);
      secret = keyAgreement.generateSecret();
    } catch (Exception e) {
      throw new RuntimeException("Is BouncyCastle in the classpath?", e);
    }
  }

  /**
   * Returns the public key
   * @return the public key
   */
  public byte[] getPublicKey() {
    return publicKey;
  }

  /**
   * Returns the pairing index
   * @return the pairing index
   */
  public byte getPairingIndex() {
    return pairingIndex;
  }

  /**
   * Establishes a Secure Channel with the card. The command parameters are the public key generated in the first step.
   * Follows the specifications from the SECURE_CHANNEL.md document.
   *
   * @param apduChannel the apdu channel
   * @return the card response
   * @throws IOException communication error
   */
  public void autoOpenSecureChannel(CardChannel apduChannel) throws IOException {
    APDUResponse response = openSecureChannel(apduChannel, pairingIndex, publicKey);

    if (response.getSw() != 0x9000) {
      throw new IOException("OPEN SECURE CHANNEL failed");
    }

    processOpenSecureChannelResponse(response);

    response = mutuallyAuthenticate(apduChannel);

    if (response.getSw() != 0x9000) {
      throw new IOException("MUTUALLY AUTHENTICATE failed");
    }

    if(!verifyMutuallyAuthenticateResponse(response)) {
      throw new IOException("Invalid authentication data from the card");
    }
  }

  /**
   * Processes the response from OPEN SECURE CHANNEL. This initialize the session keys, Cipher and MAC internally.
   *
   * @param response the card response
   */
  public void processOpenSecureChannelResponse(APDUResponse response) {
    try {
      MessageDigest md = MessageDigest.getInstance("SHA512");
      md.update(secret);
      md.update(pairingKey);
      byte[] data = response.getData();
      byte[] keyData = md.digest(Arrays.copyOf(data, SC_SECRET_LENGTH));
      iv = Arrays.copyOfRange(data, SC_SECRET_LENGTH, data.length);

      sessionEncKey = new SecretKeySpec(Arrays.copyOf(keyData, SC_SECRET_LENGTH), "AES");
      sessionMacKey = new KeyParameter(keyData, SC_SECRET_LENGTH, SC_SECRET_LENGTH);
      sessionCipher = Cipher.getInstance("AES/CBC/ISO7816-4Padding");
      sessionMac = new CBCBlockCipherMac(new AESEngine(), 128, null);
      open = true;
    } catch(Exception e) {
      throw new RuntimeException("Is BouncyCastle in the classpath?", e);
    }
  }

  /**
   * Verify that the response from MUTUALLY AUTHENTICATE is correct.
   *
   * @param response the card response
   * @return true if response is correct, false otherwise
   */
  public boolean verifyMutuallyAuthenticateResponse(APDUResponse response) {
    return response.getData().length == SC_SECRET_LENGTH;
  }

  /**
   * Handles the entire pairing procedure in order to be able to use the secure channel
   *
   * @param apduChannel the apdu channel
   * @throws IOException communication error
   */
  public void autoPair(CardChannel apduChannel, byte[] sharedSecret) throws IOException {
    byte[] challenge = new byte[32];
    random.nextBytes(challenge);
    APDUResponse resp = pair(apduChannel, PAIR_P1_FIRST_STEP, challenge);

    if (resp.getSw() != 0x9000) {
      throw new IOException("Pairing failed on step 1");
    }

    byte[] respData = resp.getData();
    byte[] cardCryptogram = Arrays.copyOf(respData, 32);
    byte[] cardChallenge = Arrays.copyOfRange(respData, 32, respData.length);
    byte[] checkCryptogram;

    MessageDigest md;

    try {
      md = MessageDigest.getInstance("SHA256");
    } catch(Exception e) {
      throw new RuntimeException("Is BouncyCastle in the classpath?", e);
    }

    md.update(sharedSecret);
    checkCryptogram = md.digest(challenge);

    if (!Arrays.equals(checkCryptogram, cardCryptogram)) {
      throw new IOException("Invalid card cryptogram");
    }

    md.update(sharedSecret);
    checkCryptogram = md.digest(cardChallenge);

    resp = pair(apduChannel, PAIR_P1_LAST_STEP, checkCryptogram);

    if (resp.getSw() != 0x9000) {
      throw new IOException("Pairing failed on step 2");
    }

    respData = resp.getData();
    md.update(sharedSecret);
    pairingKey = md.digest(Arrays.copyOfRange(respData, 1, respData.length));
    pairingIndex = respData[0];
  }

  /**
   * Unpairs the current paired key
   *
   * @param apduChannel the apdu channel
   * @throws IOException communication error
   */
  public void autoUnpair(CardChannel apduChannel) throws IOException {
    APDUResponse resp = unpair(apduChannel, pairingIndex);

    if (resp.getSw() != 0x9000) {
      throw new IOException("Unpairing failed");
    }
  }

  /**
   * Sends a OPEN SECURE CHANNEL APDU.
   *
   * @param apduChannel the apdu channel
   * @param index the P1 parameter
   * @param data the data
   * @return the raw card response
   * @throws IOException communication error
   */
  public APDUResponse openSecureChannel(CardChannel apduChannel, byte index, byte[] data) throws IOException {
    open = false;
    APDUCommand openSecureChannel = new APDUCommand(0x80, INS_OPEN_SECURE_CHANNEL, index, 0, data);
    return apduChannel.send(openSecureChannel);
  }

  /**
   * Sends a MUTUALLY AUTHENTICATE APDU. The data is generated automatically
   *
   * @param apduChannel the apdu channel
   * @return the raw card response
   * @throws IOException communication error
   */
  public APDUResponse mutuallyAuthenticate(CardChannel apduChannel) throws IOException {
    byte[] data = new byte[SC_SECRET_LENGTH];
    random.nextBytes(data);

    return mutuallyAuthenticate(apduChannel, data);
  }

  /**
   * Sends a MUTUALLY AUTHENTICATE APDU.
   *
   * @param apduChannel the apdu channel
   * @param data the data
   * @return the raw card response
   * @throws IOException communication error
   */
  public APDUResponse mutuallyAuthenticate(CardChannel apduChannel, byte[] data) throws IOException {
    APDUCommand mutuallyAuthenticate = protectedCommand(0x80, INS_MUTUALLY_AUTHENTICATE, 0, 0, data);
    return transmit(apduChannel, mutuallyAuthenticate);
  }

  /**
   * Sends a PAIR APDU.
   *
   * @param apduChannel the apdu channel
   * @param p1 the P1 parameter
   * @param data the data
   * @return the raw card response
   * @throws IOException communication error
   */
  public APDUResponse pair(CardChannel apduChannel, byte p1, byte[] data) throws IOException {
    APDUCommand openSecureChannel = new APDUCommand(0x80, INS_PAIR, p1, 0, data);
    return transmit(apduChannel, openSecureChannel);
  }

  /**
   * Sends a UNPAIR APDU.
   *
   * @param apduChannel the apdu channel
   * @param p1 the P1 parameter
   * @return the raw card response
   * @throws IOException communication error
   */
  public APDUResponse unpair(CardChannel apduChannel, byte p1) throws IOException {
    APDUCommand openSecureChannel = protectedCommand(0x80, INS_UNPAIR, p1, 0, new byte[0]);
    return transmit(apduChannel, openSecureChannel);
  }

  /**
   * Unpair all other clients
   *
   * @param apduChannel the apdu channel
   * @return the raw card response
   * @throws IOException communication error
   */
  public void unpairOthers(CardChannel apduChannel) throws IOException, APDUException {
    for (int i = 0; i < PAIRING_MAX_CLIENT_COUNT; i++) {
      if (i != pairingIndex) {
        APDUCommand openSecureChannel = protectedCommand(0x80, INS_UNPAIR, i, 0, new byte[0]);
        transmit(apduChannel, openSecureChannel).checkOK();
      }
    }
  }

  /**
   * Encrypts the plaintext data using the session key. The maximum plaintext size is 223 bytes. The returned ciphertext
   * already includes the IV and padding and can be sent as-is in the APDU payload. If the input is an empty byte array
   * the returned data will still contain the IV and padding.
   *
   * @param data the plaintext data
   * @return the encrypted data
   */
  private byte[] encryptAPDU(byte[] data) {
    assert data.length <= PAYLOAD_MAX_SIZE;

    try {
      IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);

      sessionCipher.init(Cipher.ENCRYPT_MODE, sessionEncKey, ivParameterSpec);
      return sessionCipher.doFinal(data);
    } catch(Exception e) {
      throw new RuntimeException("Is BouncyCastle in the classpath?", e);
    }
  }

  /**
   * Decrypts the response from the card using the session key. The returned data is already stripped from IV and padding
   * and can be potentially empty.
   *
   * @param data the ciphetext
   * @return the plaintext
   */
  private byte[] decryptAPDU(byte[] data) {
    try {
      IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
      sessionCipher.init(Cipher.DECRYPT_MODE, sessionEncKey, ivParameterSpec);
      return sessionCipher.doFinal(data);
    } catch(Exception e) {
      throw new RuntimeException("Is BouncyCastle in the classpath?", e);
    }
  }

  /**
   * Returns a command APDU with MAC and encrypted data.
   *
   * @param cla the CLA byte
   * @param ins the INS byte
   * @param p1 the P1 byte
   * @param p2 the P2 byte
   * @param data the data, can be an empty array but not null
   * @return the command APDU
   */
  public APDUCommand protectedCommand(int cla, int ins, int p1, int p2, byte[] data) {
    byte[] finalData;

    if (open) {
      data = encryptAPDU(data);
      byte[] meta = new byte[]{(byte) cla, (byte) ins, (byte) p1, (byte) p2, (byte) (data.length + SC_BLOCK_SIZE), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
      updateIV(meta, data);

      finalData = Arrays.copyOf(iv, iv.length + data.length);
      System.arraycopy(data, 0, finalData, iv.length, data.length);
    } else {
      finalData = data;
    }

    return new APDUCommand(cla, ins, p1, p2, finalData);
  }

  /**
   * Transmits a protected command APDU and unwraps the response data. The MAC is verified, the data decrypted and the
   * SW read from the payload.
   *
   * @param apduChannel the APDU channel
   * @param apdu the APDU to send
   * @return the unwrapped response APDU
   * @throws IOException transmission error
   */
  public APDUResponse transmit(CardChannel apduChannel, APDUCommand apdu) throws IOException {
    APDUResponse resp = apduChannel.send(apdu);

    if (resp.getSw() == 0x6982) {
      open = false;
    }

    if (open) {
      byte[] data = resp.getData();
      byte[] meta = new byte[]{(byte) data.length, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
      byte[] mac = Arrays.copyOf(data, iv.length);
      data = Arrays.copyOfRange(data, iv.length, data.length);

      byte[] plainData = decryptAPDU(data);

      updateIV(meta, data);

      if (!Arrays.equals(iv, mac)) {
        throw new IOException("Invalid MAC");
      }

      return new APDUResponse(plainData);
    } else {
      return resp;
    }
  }

  /**
   * Marks the SecureChannel as closed
   */
  public void reset() {
    open = false;
  }

  /**
   * Encrypts the payload for the INIT command
   * @param initData the payload for the INIT command
   *
   * @return the encrypted buffer
   */
  public byte[] oneShotEncrypt(byte[] initData) {
    try {
      iv = new byte[SC_BLOCK_SIZE];
      random.nextBytes(iv);
      IvParameterSpec ivParameterSpec = new IvParameterSpec(iv);
      sessionEncKey = new SecretKeySpec(secret, "AES");
      sessionCipher = Cipher.getInstance("AES/CBC/ISO7816-4Padding");
      sessionCipher.init(Cipher.ENCRYPT_MODE, sessionEncKey, ivParameterSpec);
      initData = sessionCipher.doFinal(initData);
      byte[] encrypted = new byte[1 + publicKey.length + iv.length + initData.length];
      encrypted[0] = (byte) publicKey.length;
      System.arraycopy(publicKey, 0, encrypted, 1, publicKey.length);
      System.arraycopy(iv, 0, encrypted, (1 + publicKey.length), iv.length);
      System.arraycopy(initData, 0, encrypted, (1 + publicKey.length + iv.length), initData.length);
      return encrypted;
    } catch (Exception e) {
      throw new RuntimeException("Is BouncyCastle in the classpath?", e);
    }
  }

  /**
   * Marks the SecureChannel as open. Only to be used when writing tests for the SecureChannel, in normal operation this
   * would only make things wrong.
   *
   */
  void setOpen() {
    open = true;
  }

  /**
   * Calculates a CMAC from the metadata and data provided and sets it as the IV for the next message.
   *
   * @param meta metadata
   * @param data data
   */
  private void updateIV(byte[] meta, byte[] data) {
    try {
      sessionMac.init(sessionMacKey);
      sessionMac.update(meta, 0, meta.length);
      sessionMac.update(data, 0, data.length);
      sessionMac.doFinal(iv, 0);
    } catch (Exception e) {
      throw new RuntimeException("Is BouncyCastle in the classpath?", e);
    }
  }
}
