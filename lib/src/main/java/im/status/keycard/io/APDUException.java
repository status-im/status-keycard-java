package im.status.keycard.io;

public class APDUException extends Exception {
    public final int sw;

    public APDUException(int sw, String message) {
        super(message + ", 0x" + String.format("%04X", sw));
        this.sw = sw;
    }

    public APDUException(String message) {
        super(message);
        this.sw = 0;
    }
}
