package im.status.hardwallet_lite_android.io;

public class APDUResponse {
    public static final int SW_OK = 0x9000;
    public static final int SW_SECURITY_CONDITION_NOT_SATISFIED = 0x6982;
    public static final int SW_AUTHENTICATION_METHOD_BLOCKED = 0x6983;
    public static final int SW_CARD_LOCKED = 0x6283;
    public static final int SW_REFERENCED_DATA_NOT_FOUND = 0x6A88;
    public static final int SW_CONDITIONS_OF_USE_NOT_SATISFIED = 0x6985; // applet may be already installed

    private byte[] apdu;
    private byte[] data;
    private int sw;
    private int sw1;
    private int sw2;

    public APDUResponse(byte[] apdu)  {
        if (apdu.length < 2) {
            throw new IllegalArgumentException("APDU response must be at least 2 bytes");
        }
        this.apdu = apdu;
        this.parse();
    }

    private void parse() {
        int length = this.apdu.length;

        this.sw1 = this.apdu[length - 2] & 0xff;
        this.sw2 = this.apdu[length - 1] & 0xff;
        this.sw = (this.sw1 << 8) | this.sw2;

        this.data = new byte[length - 2];
        System.arraycopy(this.apdu, 0, this.data, 0, length - 2);
    }

    public boolean isOK() {
        return this.sw == SW_OK;
    }

    public APDUResponse checkOK(int... codes) throws APDUException {
        for (int code : codes) {
            if (this.sw == code) {
                return this;
            }
        }

        if (!isOK()) {
            switch (this.sw) {
                case SW_SECURITY_CONDITION_NOT_SATISFIED:
                    throw new APDUException(this.sw, "security condition not satisfied");
                case SW_AUTHENTICATION_METHOD_BLOCKED:
                    throw new APDUException(this.sw, "authentication method blocked");
                default:
                    throw new APDUException(this.sw,  "Unexpected error SW");
            }

        }

        return this;
    }

    public byte[] getData() {
        return this.data;
    }

    public int getSw() {
        return this.sw;
    }

    public int getSw1() {
        return this.sw1;
    }

    public int getSw2() {
        return this.sw2;
    }

    public byte[] getBytes() {
        return this.apdu;
    }
}
