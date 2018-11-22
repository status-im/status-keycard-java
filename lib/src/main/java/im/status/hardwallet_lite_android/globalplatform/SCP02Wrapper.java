package im.status.hardwallet_lite_android.globalplatform;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

import im.status.hardwallet_lite_android.io.APDUCommand;

public class SCP02Wrapper {
    private byte[] macKeyData;
    private byte[] icv;

    public SCP02Wrapper(byte[] macKeyData) {
        this.macKeyData = macKeyData;
        this.icv = Crypto.NullBytes8.clone();
    }

    public APDUCommand wrap(APDUCommand cmd) {
        try {
            int cla = (cmd.getCla() | 0x04) & 0xff;
            byte[] data = cmd.getData();

            ByteArrayOutputStream macData = new ByteArrayOutputStream();
            macData.write(cla);
            macData.write(cmd.getIns());
            macData.write(cmd.getP1());
            macData.write(cmd.getP2());
            macData.write(data.length + 8);
            macData.write(data);

            byte[] icv;
            if (Arrays.equals(this.icv, Crypto.NullBytes8)) {
                icv = this.icv;
            } else {
                icv = Crypto.encryptICV(this.macKeyData, this.icv);
            }

            byte[] mac = Crypto.macFull3des(this.macKeyData, Crypto.appendDESPadding(macData.toByteArray()), icv);
            byte[] newData = new byte[data.length + mac.length];
            System.arraycopy(data, 0, newData, 0, data.length );
            System.arraycopy(mac, 0, newData, data.length, mac.length );

            APDUCommand wrapped = new APDUCommand(cla, cmd.getIns(), cmd.getP1(), cmd.getP2(), newData, cmd.getNeedsLE());
            this.icv = mac.clone();

            return wrapped;
        } catch (IOException e) {
            throw new RuntimeException("error wrapping APDU command.", e);
        }
    }

    public byte[] getICV() {
        return this.icv;
    }
}

