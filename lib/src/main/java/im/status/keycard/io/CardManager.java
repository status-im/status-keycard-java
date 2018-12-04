package im.status.keycard.io;

import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.os.SystemClock;
import android.util.Log;
import java.io.IOException;
import java.security.Security;

public class CardManager extends Thread implements NfcAdapter.ReaderCallback {

    private static final String TAG = "CardManager";
    private static final int DEFAULT_LOOP_SLEEP_MS = 50;

    private IsoDep isoDep;
    private boolean isRunning;
    private CardListener cardListener;
    private int loopSleepMS;

    public boolean isConnected() {
        return isoDep != null && isoDep.isConnected();
    }

    public CardManager() {
        this(DEFAULT_LOOP_SLEEP_MS);
    }

    public CardManager(int loopSleepMS) {
        this.loopSleepMS = loopSleepMS;
        Security.insertProviderAt(new org.spongycastle.jce.provider.BouncyCastleProvider(), 1);
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

            SystemClock.sleep(loopSleepMS);
        }
    }

    private void onCardConnected() {
        isRunning = true;
        if (cardListener != null) {
            cardListener.onConnected(new CardChannel(isoDep));
        }
        isRunning = false;
    }

    private void onCardDisconnected() {
        isRunning = false;
        isoDep = null;
        if (cardListener != null) {
            cardListener.onDisconnected();
        }
    }

    public void setCardListener(CardListener listener) {
        cardListener = listener;
    }
}
