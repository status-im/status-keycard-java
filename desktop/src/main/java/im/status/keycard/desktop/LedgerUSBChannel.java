package im.status.keycard.desktop;

import im.status.keycard.io.APDUCommand;
import im.status.keycard.io.APDUResponse;
import im.status.keycard.io.CardChannel;
import im.status.keycard.io.LedgerUtil;
import org.hid4java.HidDevice;

import java.io.IOException;

public class LedgerUSBChannel implements CardChannel {
  private static final int HID_BUFFER_SIZE = 64;
  private static final int READ_TIMEOUT = 20000;

  private HidDevice hidDevice;

  public LedgerUSBChannel(HidDevice hidDevice) {
    this.hidDevice = hidDevice;
  }

  @Override
  public APDUResponse send(APDUCommand cmd) throws IOException {
    return LedgerUtil.send(cmd, HID_BUFFER_SIZE, true, new LedgerUtil.Callback() {
      @Override
      public void write(byte[] chunk) throws IOException {
        if (hidDevice.write(chunk, chunk.length, (byte) 0x00) < 0) {
          throw new IOException("Write failed");
        }
      }

      @Override
      public void read(byte[] chunk) throws IOException {
        if (hidDevice.read(chunk, READ_TIMEOUT) < 0) {
          throw new IOException("Read failed");
        }
      }
    });
  }

  @Override
  public boolean isConnected() {
    return hidDevice.isOpen();
  }

  @Override
  public int pairingPasswordPBKDF2IterationCount() {
    return 10;
  }
}
