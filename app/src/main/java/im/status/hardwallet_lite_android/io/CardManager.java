package im.status.hardwallet_lite_android.io;

import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import android.util.Log;
import im.status.hardwallet_lite_android.wallet.WalletAppletCommandSet;
import org.spongycastle.util.encoders.Hex;

import java.io.IOException;

public class CardManager extends Thread implements NfcAdapter.ReaderCallback {
    private static final String TAG = "CardManager";

    private IsoDep isoDep;
    private boolean isRunning;

    public boolean isConnected() {
        return this.isoDep != null && this.isoDep.isConnected();
    }

    @Override
    public void onTagDiscovered(Tag tag) {
        this.isoDep = IsoDep.get(tag);

        try {
            this.isoDep = IsoDep.get(tag);
            this.isoDep.connect();
            this.isoDep.setTimeout(120000);
        } catch (IOException e) {
            Log.e(TAG, "error connecting to tag");
        }
    }

    public void run() {
        boolean connected = this.isConnected();

        while(true) {
            boolean newConnected = this.isConnected();
            if (newConnected != connected) {
                connected = newConnected;
                Log.i(TAG, "tag " + (connected ? "connected" : "disconnected"));

                if (connected && !isRunning) {
                    this.onCardConnected();
                } else {
                    this.onCardDisconnected();
                }
            }

            try {
                Thread.sleep(50);
            } catch (InterruptedException e) {
                Log.e(TAG, "error in TagManager thread: " + e.getMessage());
                this.interrupt();
            }
        }
    }

    private void onCardConnected() {
        this.isRunning = true;

        try {
            CardChannel cardChannel = new CardChannel(this.isoDep);
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

        this.isRunning = false;
    }

    private void onCardDisconnected() {
        this.isRunning = false;
        this.isoDep = null;
    }
}
