package im.status.hardwallet_lite_android.globalplatform;

import org.spongycastle.util.encoders.Hex;

import java.io.IOException;

import im.status.hardwallet_lite_android.io.APDUCommand;
import im.status.hardwallet_lite_android.io.APDUException;
import im.status.hardwallet_lite_android.io.APDUResponse;
import im.status.hardwallet_lite_android.io.CardChannel;

public class GlobalPlatformCommandSet {
    static final byte INS_SELECT = (byte) 0xA4;
    static final byte INS_INITIALIZE_UPDATE = (byte) 0x50;
    static final byte INS_EXTERNAL_AUTHENTICATE = (byte) 0x82;

    static final byte SELECT_P1_BY_NAME = (byte) 0x04;

    static final byte EXTERNAL_AUTHENTICATE_P1 = (byte) 0x01;

    private final CardChannel apduChannel;
    private SecureChannel secureChannel;
    private SCP02Keys cardKeys;
    private Session session;

    private final byte[] testKey = Hex.decode("404142434445464748494a4b4c4d4e4f");

    static final byte[] PACKAGE_AID = Hex.decode("53746174757357616C6C6574");
    static final byte[] WALLET_AID = Hex.decode("53746174757357616C6C6574417070");
    static final byte[] NDEF_APPLET_AID = Hex.decode("53746174757357616C6C65744E4643");
    static final byte[] NDEF_INSTANCE_AID = Hex.decode("D2760000850101");

    public GlobalPlatformCommandSet(CardChannel apduChannel) {
        this.apduChannel = apduChannel;
        this.cardKeys = new SCP02Keys(testKey, testKey);
    }

    public APDUResponse select() throws IOException {
        APDUCommand cmd = new APDUCommand(0x00, INS_SELECT, SELECT_P1_BY_NAME, 0, new byte[0]);
        return apduChannel.send(cmd);
    }

    public APDUResponse initializeUpdate(byte[] hostChallenge) throws IOException, APDUException {
        APDUCommand cmd = new APDUCommand(0x80, INS_INITIALIZE_UPDATE, 0, 0, hostChallenge, true);
        APDUResponse resp = apduChannel.send(cmd);
        if (resp.isOK()) {
            this.session = SecureChannel.verifyChallenge(hostChallenge, this.cardKeys, resp);
            this.secureChannel = new SecureChannel(this.apduChannel, this.session.getKeys());
        }

        return resp;
    }

    public APDUResponse externalAuthenticate(byte[] hostChallenge) throws IOException {
        byte[] cardChallenge = this.session.getCardChallenge();
        byte[] data = new byte[cardChallenge.length + hostChallenge.length];
        System.arraycopy(cardChallenge, 0, data, 0, cardChallenge.length);
        System.arraycopy(hostChallenge, 0, data, cardChallenge.length, hostChallenge.length);

        byte[] paddedData = Crypto.appendDESPadding(data);
        byte[] hostCryptogram = Crypto.mac3des(this.session.getKeys().encKeyData, paddedData, Crypto.NullBytes8);

        APDUCommand cmd = new APDUCommand(0x84, INS_EXTERNAL_AUTHENTICATE, EXTERNAL_AUTHENTICATE_P1, 0, hostCryptogram);

        return this.secureChannel.send(cmd);
    }
}
