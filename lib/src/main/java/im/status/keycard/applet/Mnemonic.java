package im.status.keycard.applet;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Scanner;

public class Mnemonic {
  private final static int WORDLIST_SIZE = 2048;

  private short[] indexes;
  private String[] wordlist;

  /**
   * Constructs a Mnemonic object from the response of the GENERATE MNEMONIC APDU
   *
   * @param data the card response
   */
  public Mnemonic(byte[] data) {
    this.indexes = new short[data.length/2];

    for (int i = 0; i < this.indexes.length; i++) {
      this.indexes[i] = (short) (((data[i * 2] & 0xff) << 8) | (data[(i * 2) + 1] & 0xff));
    }
  }

  /**
   * Sets the wordlist, which must be a list of 2048 words.
   *
   * @param wordlist
   */
  public void setWordlist(String[] wordlist) {
    if (wordlist.length != WORDLIST_SIZE) {
      throw new IllegalArgumentException("The list must contain exactly 2048 entries");
    }

    this.wordlist = wordlist;
  }

  /**
   * Returns the official BIP39 english wordlist as fetched from https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt on 23 Oct 2019.
   *
   */
  public void fetchBIP39EnglishWordlist() {
    this.wordlist = MnemonicEnglishDictionary.words;
  }

  /**
   * Gets the indexes of all words of the mnemonic.
   * @return indexes
   */
  public short[] getIndexes() {
    return indexes;
  }

  /**
   * The words of the mnemonic phrase. Requires the wordlist to be non-null.
   *
   * @return the array of words
   */
  public String[] getWords() {
    if (this.wordlist == null) {
      throw new IllegalStateException("The wordlist must be set first");
    }

    String[] words = new String[this.indexes.length];

    for (int i = 0; i < this.indexes.length; i++) {
      words[i] = this.wordlist[this.indexes[i]];
    }

    return words;
  }

  /**
   * The representation of this object as a mnemonic phrase. Requires the wordlist to be non-null.
   * @return the mnemonic phrase
   */
  public String toMnemonicPhrase() {
    return join(" ", getWords());
  }

  /**
   * The binary seed representation of this object, with no password.
   *
   * @return the binary seed
   */
  public byte[] toBinarySeed() {
    return toBinarySeed("");
  }

  /**
   * The binary seed representation of this object, with a password.
   *
   * @param password can be an empty string but not null
   * @return the binary seed
   */
  public byte[] toBinarySeed(String password) {
    return toBinarySeed(toMnemonicPhrase(), password);
  }

  /**
   * The full master key, generated from this mnemonic.
   *
   */
  public BIP32KeyPair toBIP32KeyPair() {
    return toBIP32KeyPair("");
  }

  /**
   * The full master key, generated from this mnemonic with a password.
   *
   * @param password can be an empty string but not null
   * @return the binary seed
   */
  public BIP32KeyPair toBIP32KeyPair(String password) {
    return BIP32KeyPair.fromBinarySeed(toBinarySeed(password));
  }

  public static byte[] toBinarySeed(String mnemonicPhrase, String password) {
    SecretKey key;

    try {
      SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512", "BC");
      PBEKeySpec spec = new PBEKeySpec(mnemonicPhrase.toCharArray(), ("mnemonic" + password).getBytes(), 2048, 512);
      key = skf.generateSecret(spec);
    } catch (Exception e) {
      throw new RuntimeException("Is Bouncycastle correctly initialized?");
    }

    return key.getEncoded();
  }

  /**
   * String join. Used instead of Android TextUtils.join or Java 8 String.join method for compatibility reasons.
   *
   * @param list the list of words
   * @param conjunction the conjunction
   *
   * @return the joined string
   */
  private String join(String conjunction, String[] list) {
    StringBuilder sb = new StringBuilder();
    boolean first = true;
    for (String item : list) {
      if (first) {
        first = false;
      } else {
        sb.append(conjunction);
      }

      sb.append(item);
    }

    return sb.toString();
  }
}
