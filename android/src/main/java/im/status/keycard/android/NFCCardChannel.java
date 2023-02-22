package im.status.keycard.android;

import android.nfc.tech.IsoDep;
import android.util.Log;
import im.status.keycard.io.APDUCommand;
import im.status.keycard.io.APDUResponse;
import im.status.keycard.io.CardChannel;

import java.io.IOException;

/**
 * Implementation of the CardChannel interface using the Android NFC API.
 */
public class NFCCardChannel implements CardChannel {
  private static final String TAG = "CardChannel";

  private IsoDep isoDep;

  public NFCCardChannel(IsoDep isoDep) {
    this.isoDep = isoDep;
  }

  @Override
  public APDUResponse send(APDUCommand cmd) throws IOException {
    byte[] apdu = cmd.serialize();
    Log.d(TAG, String.format("COMMAND CLA: %02X INS: %02X P1: %02X P2: %02X LC: %02X", cmd.getCla(), cmd.getIns(), cmd.getP1(), cmd.getP2(), cmd.getData().length));
    
    try {
      byte[] resp = this.isoDep.transceive(apdu);
      APDUResponse response = new APDUResponse(resp);
      Log.d(TAG, String.format("RESPONSE LEN: %02X, SW: %04X %n-----------------------", response.getData().length, response.getSw()));
      return response;
    } catch(SecurityException e) {
      throw new IOException("Tag disconnected", e);
    } catch(IllegalArgumentException e) {
      throw new IOException("Malformed card response", e);
    }
  }

  @Override
  public boolean isConnected() {
    try {
      return this.isoDep.isConnected();
    } catch(SecurityException e) {
      return false;
    }
  }
}
