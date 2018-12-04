package im.status.keycard.globalplatform;

public class Session {
    private SCP02Keys keys;
    private byte[] cardChallenge;

    public Session(SCP02Keys keys, byte[] cardChallenge) {
        this.keys = keys;
        this.cardChallenge = cardChallenge;
    }

    public SCP02Keys getKeys() {
        return keys;
    }

    public byte[] getCardChallenge() {
        return cardChallenge;
    }
}
