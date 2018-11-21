package im.status.hardwallet_lite_android.smartcard;

public class Keys {
    public byte[] encKeyData;
    public byte[] macKeyData;

    public Keys(byte[] encKeyData, byte[] macKeyData) {
        this.encKeyData = encKeyData;
        this.macKeyData = macKeyData;
    }

    public byte[] getEncKeyData() {
        return encKeyData;
    }

    public byte[] getMacKeyData() {
        return macKeyData;
    }
}
