package im.status.keycard.globalplatform;

/**
 * SCP02 Session.
 */
public class Session {
  private SCP02Keys keys;
  private byte[] cardChallenge;

  /**
   * Constructs the SCP02 session.
   *
   * @param keys the session keys
   * @param cardChallenge the card challenge
   */
  public Session(SCP02Keys keys, byte[] cardChallenge) {
    this.keys = keys;
    this.cardChallenge = cardChallenge;
  }

  /**
   * The SCP02 keys
   * @return SCP02 keys
   */
  public SCP02Keys getKeys() {
    return keys;
  }

  /**
   * The card challenge
   * @return card challenge
   */
  public byte[] getCardChallenge() {
    return cardChallenge;
  }
}
