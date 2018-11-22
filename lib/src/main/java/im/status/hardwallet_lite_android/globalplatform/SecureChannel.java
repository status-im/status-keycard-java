package im.status.hardwallet_lite_android.globalplatform;

import java.io.IOException;

import im.status.hardwallet_lite_android.io.APDUCommand;
import im.status.hardwallet_lite_android.io.APDUException;
import im.status.hardwallet_lite_android.io.APDUResponse;
import im.status.hardwallet_lite_android.io.CardChannel;

public class SecureChannel {
    private CardChannel channel;
    private SCP02Wrapper wrapper;

    public static byte[] DERIVATION_PURPOSE_ENC = new byte[]{(byte) 0x01, (byte) 0x82};
    public static byte[] DERIVATION_PURPOSE_MAC = new byte[]{(byte) 0x01, (byte) 0x01};
    public static byte[] DERIVATION_PURPOSE_DEK = new byte[]{(byte) 0x01, (byte) 0x81};

    public SecureChannel(CardChannel channel, Keys keys) {
        this.channel = channel;
        this.wrapper = new SCP02Wrapper(keys.getMacKeyData());
    }

    public APDUResponse send(APDUCommand cmd) throws IOException {
        APDUCommand wrappedCommand = this.wrapper.wrap(cmd);
        return this.channel.send(wrappedCommand);
    }

    public static Session verifyChallenge(byte[] hostChallenge, Keys cardKeys, APDUResponse resp) throws APDUException {
        if (resp.getSw() == APDUResponse.SW_SECURITY_CONDITION_NOT_SATISFIED) {
            throw new APDUException(resp.getSw(), "security condition not satisfied");
        }

        if (resp.getSw() == APDUResponse.SW_AUTHENTICATION_METHOD_BLOCKED) {
            throw new APDUException(resp.getSw(), "authentication method blocked");
        }

        byte[] data = resp.getData();

        if (data.length != 28) {
            throw new APDUException(resp.getSw(), String.format("bad data length, expected 28, got %d", data.length));
        }

        byte[] cardChallenge = new byte[8];
        System.arraycopy(data, 12, cardChallenge, 0, 8);

        byte[] cardCryptogram = new byte[8];
        System.arraycopy(data, 20, cardCryptogram, 0, 8);

        byte[] seq = new byte[2];
        System.arraycopy(data, 12, seq, 0, 2);

        byte[] sessionEncKey = Crypto.deriveSCP02SessionKey(cardKeys.getEncKeyData(), seq, DERIVATION_PURPOSE_ENC);
        byte[] sessionMacKey = Crypto.deriveSCP02SessionKey(cardKeys.getMacKeyData(), seq, DERIVATION_PURPOSE_MAC);

        Keys sessionKeys = new Keys(sessionEncKey, sessionMacKey);

        boolean verified = Crypto.verifyCryptogram(sessionKeys.getEncKeyData(), hostChallenge, cardChallenge, cardCryptogram);
        if (!verified) {
            throw new APDUException("error verifying card cryptogram.");
        }

        return new Session(sessionKeys, cardChallenge);
    }
}
