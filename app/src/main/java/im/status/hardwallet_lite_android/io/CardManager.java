package im.status.hardwallet_lite_android.io;

import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.os.SystemClock;
import android.util.Log;
import java.io.IOException;

public class CardManager extends Thread implements NfcAdapter.ReaderCallback {
    private static final String TAG = "CardManager";

    private IsoDep isoDep;
    private boolean isRunning;
    private OnCardConnectedListener onCardConnectedListener;

    public boolean isConnected() {
        return isoDep != null && isoDep.isConnected();
    }

    @Override
    public void onTagDiscovered(Tag tag) {
        isoDep = IsoDep.get(tag);

        try {
            isoDep = IsoDep.get(tag);
            isoDep.connect();
            isoDep.setTimeout(120000);
        } catch (IOException e) {
            Log.e(TAG, "error connecting to tag");
        }
    }

    public void run() {
        boolean connected = isConnected();

        while (true) {
            boolean newConnected = isConnected();
            if (newConnected != connected) {
                connected = newConnected;
                Log.i(TAG, "tag " + (connected ? "connected" : "disconnected"));

                if (connected && !isRunning) {
                    onCardConnected();
                } else {
                    onCardDisconnected();
                }
            }

            SystemClock.sleep(50);
        }
    }

    private void onCardConnected() {
        isRunning = true;

        onCardConnectedListener.onConnected(new CardChannel(isoDep));

        isRunning = false;
    }

    private void onCardDisconnected() {
        isRunning = false;
        isoDep = null;
    }

    public void setOnConnectedListener(OnCardConnectedListener onConnectedListener) {
        onCardConnectedListener = onConnectedListener;
    }
}
