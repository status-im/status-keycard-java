package im.status.keycard.app;

import android.nfc.NfcAdapter;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;
import im.status.keycard.demo.R;
import im.status.keycard.io.CardChannel;
import im.status.keycard.io.CardListener;
import im.status.keycard.android.NFCCardManager;
import im.status.keycard.applet.*;
import org.spongycastle.util.encoders.Hex;

public class MainActivity extends AppCompatActivity {

  private static final String TAG = "MainActivity";

  private NfcAdapter nfcAdapter;
  private NFCCardManager cardManager;

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_main);
    nfcAdapter = NfcAdapter.getDefaultAdapter(this);
    cardManager = new NFCCardManager();

    cardManager.setCardListener(new CardListener() {
      @Override
      public void onConnected(CardChannel cardChannel) {
        try {
          // Applet-specific code
          KeycardCommandSet cmdSet = new KeycardCommandSet(cardChannel);

          Log.i(TAG, "Applet selection successful");

          // First thing to do is selecting the applet on the card.
          ApplicationInfo info = new ApplicationInfo(cmdSet.select().checkOK().getData());

          // If the card is not initialized, the INIT apdu must be sent. The actual PIN, PUK and pairing password values
          // can be either generated or chosen by the user. Using fixed values is highly discouraged.
          if (!info.isInitializedCard()) {
            Log.i(TAG, "Initializing card with test secrets");
            cmdSet.init("000000", "123456789012", "KeycardTest").checkOK();
            info = new ApplicationInfo(cmdSet.select().checkOK().getData());
          }

          Log.i(TAG, "Instance UID: " + Hex.toHexString(info.getInstanceUID()));
          Log.i(TAG, "Secure channel public key: " + Hex.toHexString(info.getSecureChannelPubKey()));
          Log.i(TAG, "Application version: " + info.getAppVersionString());
          Log.i(TAG, "Free pairing slots: " + info.getFreePairingSlots());
          if (info.hasMasterKey()) {
            Log.i(TAG, "Key UID: " + Hex.toHexString(info.getKeyUID()));
          } else {
            Log.i(TAG, "The card has no master key");
          }

          // In real projects, the pairing key should be saved and used for all new sessions.
          cmdSet.autoPair("KeycardTest");
          Pairing pairing = cmdSet.getPairing();

          // Never log the pairing key in a real application!
          Log.i(TAG, "Pairing with card is done.");
          Log.i(TAG, "Pairing index: " + pairing.getPairingIndex());
          Log.i(TAG, "Pairing key: " + Hex.toHexString(pairing.getPairingKey()));

          // Opening a Secure Channel is needed for all other applet commands
          cmdSet.autoOpenSecureChannel();

          Log.i(TAG, "Secure channel opened. Getting applet status.");

          // We send a GET STATUS command, which does not require PIN authentication
          ApplicationStatus status = new ApplicationStatus(cmdSet.getStatus(KeycardCommandSet.GET_STATUS_P1_APPLICATION).checkOK().getData());

          Log.i(TAG, "PIN retry counter: " + status.getPINRetryCount());
          Log.i(TAG, "PUK retry counter: " + status.getPUKRetryCount());
          Log.i(TAG, "Has master key: " + status.hasMasterKey());

          // A mnemonic can be generated before PIN authentication. Generating a mnemonic does not create keys on the
          // card. a subsequent loadKey step must be performed after PIN authentication. In this example we will only
          // show how to convert the output of the card to a usable format but won't actually load the key
          Mnemonic mnemonic = new Mnemonic(cmdSet.generateMnemonic(KeycardCommandSet.GENERATE_MNEMONIC_12_WORDS).checkOK().getData());

          // We need to set a wordlist if we plan using this object to derive the binary seed. If we just need the word
          // indexes we can skip this step and call mnemonic.getIndexes() instead.
          mnemonic.fetchBIP39EnglishWordlist();

          Log.i(TAG, "Generated mnemonic phrase: " + mnemonic.toMnemonicPhrase());
          Log.i(TAG, "Binary seed: " + Hex.toHexString(mnemonic.toBinarySeed()));

          // PIN authentication allows execution of privileged commands
          cmdSet.verifyPIN("000000").checkOK();

          Log.i(TAG, "Pin Verified.");

          // If the card has no keys, we generate a new set. Keys can also be loaded on the card starting from a binary
          // seed generated from a mnemonic phrase. In alternative, we could load the generated keypair as shown in the
          // commented line of code.
          if (!status.hasMasterKey()) {
            cmdSet.generateKey();
            //cmdSet.loadKey(mnemonic.toBIP32KeyPair());
          }

          // Get the current key path using GET STATUS
          KeyPath currentPath = new KeyPath(cmdSet.getStatus(KeycardCommandSet.GET_STATUS_P1_KEY_PATH).checkOK().getData());
          Log.i(TAG, "Current key path: " + currentPath);

          if (!currentPath.toString().equals("m/44'/0'/0'/0/0")) {
            // Key derivation is needed to select the desired key. The derived key remains current until a new derive
            // command is sent (it is not lost on power loss).
            cmdSet.deriveKey("m/44'/0'/0'/0/0").checkOK();
            Log.i(TAG, "Derived m/44'/0'/0'/0/0");
          }

          // We retrieve the wallet public key
          BIP32KeyPair walletPublicKey = BIP32KeyPair.fromTLV(cmdSet.exportCurrentKey(true).checkOK().getData());

          Log.i(TAG, "Wallet public key: " + Hex.toHexString(walletPublicKey.getPublicKey()));
          Log.i(TAG, "Wallet address: " + Hex.toHexString(walletPublicKey.toEthereumAddress()));

          byte[] hash = "thiscouldbeahashintheorysoitisok".getBytes();

          RecoverableSignature signature = new RecoverableSignature(hash, cmdSet.sign(hash).checkOK().getData());

          Log.i(TAG, "Signed hash: " + Hex.toHexString(hash));
          Log.i(TAG, "Recovery ID: " + signature.getRecId());
          Log.i(TAG, "R: " + Hex.toHexString(signature.getR()));
          Log.i(TAG, "S: " + Hex.toHexString(signature.getS()));

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

      @Override
      public void onDisconnected() {
        Log.i(TAG, "Card disconnected.");
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
