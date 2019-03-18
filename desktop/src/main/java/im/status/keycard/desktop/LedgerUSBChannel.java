package im.status.keycard.desktop;

import im.status.keycard.io.APDUCommand;
import im.status.keycard.io.APDUResponse;
import im.status.keycard.io.CardChannel;
import org.hid4java.HidDevice;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class LedgerUSBChannel implements CardChannel {
  private static final int HID_BUFFER_SIZE = 64;
  private static final int LEDGER_DEFAULT_CHANNEL = 1;
  private static final int TAG_APDU = 0x05;
  private static final int READ_TIMEOUT = 20000;

  private HidDevice hidDevice;

  public LedgerUSBChannel(HidDevice hidDevice) {
    this.hidDevice = hidDevice;

  }

  @Override
  public APDUResponse send(APDUCommand cmd) throws IOException {
    ByteArrayOutputStream response = new ByteArrayOutputStream();

    int offset = 0;

    byte[] command = wrapCommandAPDU(cmd.serialize());

    byte[] chunk = new byte[HID_BUFFER_SIZE];

    while(offset != command.length) {
      System.arraycopy(command, offset, chunk, 0, HID_BUFFER_SIZE);

      if (hidDevice.write(chunk, HID_BUFFER_SIZE, (byte) 0x00) < 0) {
        throw new IOException("Write failed");
      }

      offset += HID_BUFFER_SIZE;
    }

    byte[] responseData = null;

    while ((responseData = unwrapResponseAPDU(response.toByteArray())) == null) {
      if (hidDevice.read(chunk, READ_TIMEOUT) < 0) {
        throw new IOException("Read failed");
      }

      response.write(chunk, 0, HID_BUFFER_SIZE);
    }

    return new APDUResponse(responseData);
  }

  private byte[] unwrapResponseAPDU(byte[] data) throws IOException {
    if ((data == null) || (data.length < 7 + 5)) {
      return null;
    }

    int sequenceIdx = 0;
    int offset = checkResponseHeader(data, 0, sequenceIdx);

    int  responseLength = ((data[offset++] & 0xff) << 8);
    responseLength |= (data[offset++] & 0xff);

    if (data.length < 7 + responseLength) {
      return null;
    }

    ByteArrayOutputStream response = new ByteArrayOutputStream();

    int blockSize = (responseLength > HID_BUFFER_SIZE - 7 ? HID_BUFFER_SIZE - 7 : responseLength);
    response.write(data, offset, blockSize);
    offset += blockSize;

    while (response.size() != responseLength) {
      sequenceIdx++;

      if (offset == data.length) {
        return null;
      }

      offset = checkResponseHeader(data, offset, sequenceIdx);

      blockSize = (responseLength - response.size() > HID_BUFFER_SIZE - 5 ? HID_BUFFER_SIZE - 5 : responseLength - response.size());
      if (blockSize > data.length - offset) {
        return null;
      }
      response.write(data, offset, blockSize);
      offset += blockSize;
    }

    return response.toByteArray();
  }

  private int checkResponseHeader(byte[] data, int offset, int sequenceIdx) throws IOException {
    if (data[offset++] != (LEDGER_DEFAULT_CHANNEL >> 8)) {
      throw new IOException("Invalid channel");
    }

    if (data[offset++] != (LEDGER_DEFAULT_CHANNEL & 0xff)) {
      throw new IOException("Invalid channel");
    }

    if (data[offset++] != TAG_APDU) {
      throw new IOException("Invalid tag");
    }

    if (data[offset++] != (sequenceIdx >> 8)) {
      throw new IOException("Invalid sequence");
    }

    if (data[offset++] != (sequenceIdx & 0xff)) {
      throw new IOException("Invalid sequence");
    }
    return offset;
  }

  private byte[] wrapCommandAPDU(byte[] command) {
    ByteArrayOutputStream output = new ByteArrayOutputStream();

    int sequenceIdx = 0;
    int offset = 0;
    writeCommandHeader(output, sequenceIdx);
    sequenceIdx++;

    output.write(command.length >> 8);
    output.write(command.length);
    int blockSize = (command.length > (HID_BUFFER_SIZE - 7) ? (HID_BUFFER_SIZE - 7) : command.length);
    output.write(command, offset, blockSize);
    offset += blockSize;

    while (offset != command.length) {
      writeCommandHeader(output, sequenceIdx);
      sequenceIdx++;

      blockSize = ((command.length - offset) > (HID_BUFFER_SIZE - 5) ? (HID_BUFFER_SIZE - 5) : (command.length - offset));
      output.write(command, offset, blockSize);
      offset += blockSize;
    }

    if ((output.size() % HID_BUFFER_SIZE) != 0) {
      byte[] padding = new byte[HID_BUFFER_SIZE - (output.size() % HID_BUFFER_SIZE)];
      output.write(padding, 0, padding.length);
    }

    return output.toByteArray();
  }

  private void writeCommandHeader(ByteArrayOutputStream output, int sequenceIdx) {
    output.write(LEDGER_DEFAULT_CHANNEL >> 8);
    output.write(LEDGER_DEFAULT_CHANNEL);
    output.write(TAG_APDU);
    output.write(sequenceIdx >> 8);
    output.write(sequenceIdx);
  }

  @Override
  public boolean isConnected() {
    return hidDevice.isOpen();
  }
}
