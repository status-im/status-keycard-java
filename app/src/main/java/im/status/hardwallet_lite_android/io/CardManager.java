package im.status.hardwallet_lite_android.io;

import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.os.SystemClock;
import android.util.Log;
import im.status.hardwallet_lite_android.wallet.WalletAppletCommandSet;
import java.io.IOException;
import org.spongycastle.util.encoders.Hex;

public class CardManager extends Thread implements NfcAdapter.ReaderCallback {
    private static final String TAG = "CardManager";

    private IsoDep isoDep;
    private boolean isRunning;

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

        while(true) {
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

        try {
            CardChannel cardChannel = new CardChannel(isoDep);
            // Applet-specific code
            WalletAppletCommandSet cmdSet = new WalletAppletCommandSet(cardChannel);

            // First thing to do is selecting the applet on the card.
            cmdSet.select().checkOK();

            // In real projects, the pairing key should be saved and used for all new sessions.
            cmdSet.autoPair("WalletAppletTest");

            // Opening a Secure Channel is needed for all other applet commands
            cmdSet.autoOpenSecureChannel();

            // We send a GET STATUS command, which does not require PIN authentication
            APDUResponse resp = cmdSet.getStatus(WalletAppletCommandSet.GET_STATUS_P1_APPLICATION).checkOK();

            // PIN authentication allows execution of privileged commands
            cmdSet.verifyPIN("000000").checkOK();

            // Cleanup, in a real application you would not unpair and instead keep the pairing key for successive interactions.
            // We also remove all other pairings so that we do not fill all slots with failing runs. Again in real application
            // this would be a very bad idea to do.
            cmdSet.unpairOthers();
            cmdSet.autoUnpair();

            Log.i(TAG, "GET STATUS response: " + Hex.toHexString(resp.getData()));
        } catch (Exception e) {
            Log.e(TAG, e.getMessage());
        }

        isRunning = false;
    }

    private void onCardDisconnected() {
        isRunning = false;
        isoDep = null;
    }
}
