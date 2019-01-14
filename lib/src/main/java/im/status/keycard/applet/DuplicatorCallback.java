package im.status.keycard.applet;

/**
 * Callback interface for duplication procedure.
 */
public interface DuplicatorCallback {
  /**
   * Must return the pairing for the current card, represented by the applicationInfo parameter. If no pairing
   * could be found, null must be returned.
   *
   * @param applicationInfo the application info template of the currently inserted card
   * @return the pairing info or null
   */
  Pairing getPairing(ApplicationInfo applicationInfo);

  /**
   * Must return the PIN for the current card. This method can prompt the user or return a cached value.
   *
   * @param applicationInfo the application info template of the currently inserted card
   * @param remainingAttempts the number of remaining PIN attempts
   * @return the PIN
   */
  String getPIN(ApplicationInfo applicationInfo, int remainingAttempts);
}
