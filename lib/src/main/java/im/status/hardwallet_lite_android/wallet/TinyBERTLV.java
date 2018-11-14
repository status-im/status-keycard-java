package im.status.hardwallet_lite_android.wallet;

import java.util.Arrays;

/**
 * Tiny BER-TLV implementation. Not for general usage, but fast and easy to use for this project.
 */
public class TinyBERTLV {
  public static final byte TLV_BOOL = (byte) 0x01;
  public static final byte TLV_INT = (byte) 0x02;

  private byte[] buffer;
  private int pos;

  public TinyBERTLV(byte[] buffer) {
    this.buffer = buffer;
    this.pos = 0;
  }

  /**
   * Enters a constructed TLV with the given tag
   *
   * @param tag the tag to enter
   * @return the length of the TLV
   * @throws IllegalArgumentException if the next tag does not match the given one
   */
  public int enterConstructed(int tag) throws IllegalArgumentException {
    checkTag(tag, readTag());
    return readLength();
  }

  /**
   * Reads a primitive TLV with the given tag
   *
   * @param tag the tag to read
   * @return the body of the TLV
   * @throws IllegalArgumentException if the next tag does not match the given one
   */
  public byte[] readPrimitive(int tag) throws IllegalArgumentException {
    checkTag(tag, readTag());
    int len = readLength();
    pos += len;
    return Arrays.copyOfRange(buffer, (pos - len), pos);
  }

  /**
   * Reads a boolean TLV.
   *
   * @return the boolean value of the TLV
   * @throws IllegalArgumentException if the next tag is not a boolean
   */
  public boolean readBoolean() throws IllegalArgumentException {
    byte[] val = readPrimitive(TLV_BOOL);
    return ((val[0] & 0xff) == 0xff);
  }

  /**
   * Reads an integer TLV.
   *
   * @return the integer value of the TLV
   * @throws IllegalArgumentException if the next tlv is not an integer or is of unsupported length
   */
  public int readInt() throws IllegalArgumentException {
    byte[] val = readPrimitive(TLV_INT);

    switch (val.length) {
      case 1:
        return val[0] & 0xff;
      case 2:
        return ((val[0] & 0xff) << 8) | (val[1] & 0xff);
      case 3:
        return ((val[0] & 0xff) << 16) | ((val[1] & 0xff) << 8) | (val[2] & 0xff);
      case 4:
        return ((val[0] & 0xff) << 24) | ((val[1] & 0xff) << 16) | ((val[2] & 0xff) << 8) | (val[3] & 0xff);
      default:
        throw new IllegalArgumentException("Integers of length " + val.length + " are unsupported");
    }
  }

  /**
   * Low-level method to unread the last read tag. Only valid if the previous call was readTag().
   */
  public void unreadLastTag() {
    pos--;
  }

  /**
   * Reads the next tag. The current implementation only reads tags on one byte. Can be extended if needed.
   *
   * @return the tag
   */
  public int readTag() {
    return buffer[pos++];
  }

  /**
   * Reads the next tag. The current implementation only reads length on one and two bytes. Can be extended if needed.
   *
   * @return the tag
   */
  public int readLength() {
    int len = buffer[pos++] & 0xff;

    if (len == 0x81) {
      len = buffer[pos++] & 0xff;
    }

    return len;
  }

  private void checkTag(int expected, int actual) throws IllegalArgumentException {
    if (expected != actual) {
      unreadLastTag();
      throw new IllegalArgumentException("Expected tag: " + expected + ", received: " + actual);
    }
  }
}
