package im.status.hardwallet_lite_android.globalplatform;

import org.spongycastle.util.encoders.Hex;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import im.status.hardwallet_lite_android.io.APDUCommand;
import im.status.hardwallet_lite_android.io.APDUException;
import im.status.hardwallet_lite_android.io.APDUResponse;
import im.status.hardwallet_lite_android.io.CardChannel;

public class GlobalPlatformCommandSet {
    static final byte INS_SELECT = (byte) 0xA4;
    static final byte INS_INITIALIZE_UPDATE = (byte) 0x50;
    static final byte INS_EXTERNAL_AUTHENTICATE = (byte) 0x82;
    static final byte INS_DELETE = (byte) 0xE4;
    static final byte INS_INSTALL = (byte) 0xE6;
    static final byte INS_LOAD = (byte) 0xE8;

    static final byte SELECT_P1_BY_NAME = (byte) 0x04;
    static final byte EXTERNAL_AUTHENTICATE_P1 = (byte) 0x01;
    static final byte INSTALL_FOR_LOAD_P1 = (byte) 0x02;
    static final byte INSTALL_FOR_INSTALL_P1 = (byte) 0x0C;
    static final byte LOAD_P1_MORE_BLOCKS = (byte) 0x00;
    static final byte LOAD_P1_LAST_BLOCK = (byte) 0x80;

    private final CardChannel apduChannel;
    private SecureChannel secureChannel;
    private SCP02Keys cardKeys;
    private Session session;

    private final byte[] testKey = Hex.decode("404142434445464748494a4b4c4d4e4f");

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

    public APDUResponse delete(byte[] aid) throws IOException {
        byte[] data = new byte[aid.length + 2];
        data[0] = 0x4F;
        data[1] = (byte) aid.length;
        System.arraycopy(aid, 0, data, 2, aid.length);

        APDUCommand cmd = new APDUCommand(0x80, INS_DELETE, 0, 0, data);

        return this.secureChannel.send(cmd);
    }

    public APDUResponse installForLoad(byte[] aid, byte[] sdaid) throws IOException {
        ByteArrayOutputStream data = new ByteArrayOutputStream();
        data.write(aid.length);
        data.write(aid);
        data.write(sdaid.length);
        data.write(sdaid);

        // empty hash length and hash
        data.write(0x00);
        data.write(0x00);
        data.write(0x00);

        APDUCommand cmd = new APDUCommand(0x80, INS_INSTALL, INSTALL_FOR_LOAD_P1, 0, data.toByteArray());

        return this.secureChannel.send(cmd);
    }

    public APDUResponse load(byte[] data, int count, boolean hasMoreBlocks) throws IOException {
        int p1 = hasMoreBlocks ? LOAD_P1_MORE_BLOCKS : LOAD_P1_LAST_BLOCK;
        APDUCommand cmd = new APDUCommand(0x80, INS_LOAD, p1, count, data);
        return this.secureChannel.send(cmd);
    }

    public APDUResponse installForInstall(byte[] packageAID, byte[] appletAID, byte[] instanceAID, byte[] params) throws IOException {
        ByteArrayOutputStream data = new ByteArrayOutputStream();
        data.write(packageAID.length);
        data.write(packageAID);
        data.write(appletAID.length);
        data.write(appletAID);
        data.write(instanceAID.length);
        data.write(instanceAID);

        byte[] privileges = new byte[]{0x00};
        data.write(privileges.length);
        data.write(privileges);

        byte[] fullParams = new byte[2 + params.length];
        fullParams[0] = (byte) 0xC9;
        fullParams[1] = (byte) params.length;
        System.arraycopy(params, 0, fullParams, 2, params.length);

        data.write(fullParams.length);
        data.write(fullParams);

        // empty perform token
        data.write(0x00);
        APDUCommand cmd = new APDUCommand(0x80, INS_INSTALL, INSTALL_FOR_INSTALL_P1, 0, data.toByteArray());

        return this.secureChannel.send(cmd);
    }
}
