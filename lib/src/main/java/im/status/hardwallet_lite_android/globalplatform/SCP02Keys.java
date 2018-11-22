package im.status.hardwallet_lite_android.globalplatform;

public class SCP02Keys {
    public byte[] encKeyData;
    public byte[] macKeyData;

    public SCP02Keys(byte[] encKeyData, byte[] macKeyData) {
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
