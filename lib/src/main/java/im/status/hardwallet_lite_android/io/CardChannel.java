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
        Log.d(TAG, String.format("COMMAND CLA: %02X INS: %02X P1: %02X P2: %02X LC: %02X", cmd.getCla(), cmd.getIns(), cmd.getP1(), cmd.getP2(), cmd.getData().length));
        byte[] resp = this.isoDep.transceive(apdu);
        APDUResponse response = new APDUResponse(resp);
        Log.d(TAG, String.format("RESPONSE LEN: %02X, SW: %04X %n-----------------------", response.getData().length, response.getSw()));
        return response;
    }

    public boolean isConnected() {
        return this.isoDep.isConnected();
    }
}
