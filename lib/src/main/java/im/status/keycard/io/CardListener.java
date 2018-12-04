package im.status.keycard.io;

public interface CardListener {
    void onConnected(CardChannel channel);
    void onDisconnected();
}
