package im.status.keycard.applet;

import org.bouncycastle.util.encoders.Hex;

public class Identifiers {
  public static final byte[] PACKAGE_AID = Hex.decode("53746174757357616C6C6574");

  public static final byte[] KEYCARD_AID = Hex.decode("53746174757357616C6C6574417070");

  public static final byte[] NDEF_AID = Hex.decode("53746174757357616C6C65744E4643");
  public static final byte[] NDEF_INSTANCE_AID = Hex.decode("D2760000850101");

  /**
   * Gets the instance AID of the Keycard applet. Since multiple instances this is a method instead of a constant.
   * Soon a method taking an additional instance index will be added.
   *
   * @return the instance AID of the Keycard applet
   */
  public static byte[] getKeycardInstanceAID() {
    return KEYCARD_AID;
  }
}
