package im.status.hardwallet_lite_android.io;

public interface CardListener {
    void onConnected(CardChannel channel);
    void onDisconnected();
}
