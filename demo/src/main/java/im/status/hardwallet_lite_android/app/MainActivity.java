package im.status.hardwallet_lite_android.app;

import android.nfc.NfcAdapter;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import im.status.hardwallet_lite_android.demo.R;
import im.status.hardwallet_lite_android.io.APDUResponse;
import im.status.hardwallet_lite_android.io.CardChannel;
import im.status.hardwallet_lite_android.io.CardManager;
import im.status.hardwallet_lite_android.io.OnCardConnectedListener;
import im.status.hardwallet_lite_android.wallet.WalletAppletCommandSet;

public class MainActivity extends AppCompatActivity {

  private static final String TAG = "MainActivity";

  private NfcAdapter nfcAdapter;
  private CardManager cardManager;

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_main);
    nfcAdapter = NfcAdapter.getDefaultAdapter(this);
    cardManager = new CardManager();

    cardManager.setOnCardConnectedListener(new OnCardConnectedListener() {
      @Override
      public void onConnected(CardChannel cardChannel) {
        try {

          Log.i(TAG, "onCardConnected()");

          // Applet-specific code
          WalletAppletCommandSet cmdSet = new WalletAppletCommandSet(cardChannel);

          // First thing to do is selecting the applet on the card.
          cmdSet.select().checkOK();

          Log.i(TAG, "Applet is installed on the connected card.");

          // In real projects, the pairing key should be saved and used for all new sessions.
          cmdSet.autoPair("WalletAppletTest");

          Log.i(TAG, "Pairing with card is done.");

          // Opening a Secure Channel is needed for all other applet commands
          cmdSet.autoOpenSecureChannel();

          Log.i(TAG, "Secure channel opened.");

          // We send a GET STATUS command, which does not require PIN authentication
          APDUResponse resp = cmdSet.getStatus(WalletAppletCommandSet.GET_STATUS_P1_APPLICATION).checkOK();

          Log.i(TAG, "Got status (response length=" + resp.getData().length + ")." );

          // PIN authentication allows execution of privileged commands
          cmdSet.verifyPIN("000000").checkOK();

          Log.i(TAG, "Pin Verified.");

          // Cleanup, in a real application you would not unpair and instead keep the pairing key for successive interactions.
          // We also remove all other pairings so that we do not fill all slots with failing runs. Again in real application
          // this would be a very bad idea to do.
          cmdSet.unpairOthers();
          cmdSet.autoUnpair();

          Log.i(TAG, "Unpaired.");

        } catch (Exception e) {
          Log.e(TAG, e.getMessage());
        }

      }
    });
    cardManager.start();
  }

  @Override
  public void onResume() {
    super.onResume();
    if (nfcAdapter != null) {
      nfcAdapter.enableReaderMode(this, this.cardManager, NfcAdapter.FLAG_READER_NFC_A | NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK, null);
    }
  }

  @Override
  public void onPause() {
    super.onPause();
    if (nfcAdapter != null) {
      nfcAdapter.disableReaderMode(this);
    }
  }
}
