package im.status.keycard.io;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class APDUCommand {
    protected int cla;
    protected int ins;
    protected int p1;
    protected int p2;
    protected int lc;
    protected byte[] data;
    protected boolean needsLE;

    public APDUCommand(int cla, int ins, int p1, int p2, byte[] data) {
        this(cla, ins, p1, p2, data, false);
    }

    public APDUCommand(int cla, int ins, int p1, int p2, byte[] data, boolean needsLE) {
        this.cla = cla & 0xff;
        this.ins = ins & 0xff;
        this.p1 = p1 & 0xff;
        this.p2 = p2 & 0xff;
        this.data = data;
        this.needsLE = needsLE;
    }

    public byte[] serialize() throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        out.write(this.cla);
        out.write(this.ins);
        out.write(this.p1);
        out.write(this.p2);
        out.write(this.data.length);
        out.write(this.data);

        if (this.needsLE) {
            out.write(0); // Response length
        }

        return out.toByteArray();
    }

    public int getCla() {
        return cla;
    }

    public int getIns() {
        return ins;
    }

    public int getP1() {
        return p1;
    }

    public int getP2() {
        return p2;
    }

    public byte[] getData() {
        return data;
    }

    public boolean getNeedsLE() {
        return this.needsLE;
    }
}
