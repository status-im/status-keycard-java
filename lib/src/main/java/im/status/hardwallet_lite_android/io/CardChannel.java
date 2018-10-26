package im.status.hardwallet_lite_android.io;

import android.nfc.tech.IsoDep;
import android.util.Log;
import org.spongycastle.util.encoders.Hex;

import java.io.IOException;

public class CardChannel {
    private static final String TAG = "CardChannel";

    private IsoDep isoDep;

    public CardChannel(IsoDep isoDep) {
        this.isoDep = isoDep;
    }

    public APDUResponse send(APDUCommand cmd) throws IOException {
        byte[] apdu = cmd.serialize();
        Log.d(TAG, String.format("COMMAND  %s", Hex.toHexString(apdu)));
        byte[] resp = this.isoDep.transceive(apdu);
        Log.d(TAG, String.format("RESPONSE %s %n-----------------------", Hex.toHexString(resp)));
        return new APDUResponse(resp);
    }
}
