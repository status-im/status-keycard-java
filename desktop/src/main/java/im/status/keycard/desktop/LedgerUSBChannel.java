package im.status.keycard.desktop;

import im.status.keycard.io.APDUCommand;
import im.status.keycard.io.APDUResponse;
import im.status.keycard.io.CardChannel;
import org.hid4java.HidDevice;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;

public class LedgerUSBChannel implements CardChannel {
  private static final int HID_BUFFER_SIZE = 64;
  private static final int LEDGER_DEFAULT_CHANNEL = 1;
  private static final int TAG_APDU = 0x05;

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
      int blockSize = (command.length - offset > HID_BUFFER_SIZE ? HID_BUFFER_SIZE : command.length - offset);
      System.arraycopy(command, offset, chunk, 0, blockSize);

      if (hidDevice.write(command, blockSize, (byte) 0x00) < 0) {
        throw new IOException("Write failed");
      }

      offset += blockSize;
    }

    byte[] responseData = null;

    while ((responseData = unwrapResponseAPDU(response.toByteArray())) == null) {
      if (hidDevice.read(chunk, 500) < 0) {
        throw new IOException("Read failed");
      }

      response.write(chunk, 0, HID_BUFFER_SIZE);
    }

    return new APDUResponse(responseData);
  }

  private byte[] unwrapResponseAPDU(byte[] data) throws IOException {
    ByteArrayOutputStream response = new ByteArrayOutputStream();
    int offset = 0;
    int responseLength;
    int sequenceIdx = 0;

    if ((data == null) || (data.length < 7 + 5)) {
      return null;
    }

    if (data[offset++] != (LEDGER_DEFAULT_CHANNEL >> 8)) {
      throw new IOException("Invalid channel");
    }

    if (data[offset++] != (LEDGER_DEFAULT_CHANNEL & 0xff)) {
      throw new IOException("Invalid channel");
    }

    if (data[offset++] != TAG_APDU) {
      throw new IOException("Invalid tag");
    }

    if (data[offset++] != 0x00) {
      throw new IOException("Invalid sequence");
    }

    if (data[offset++] != 0x00) {
      throw new IOException("Invalid sequence");
    }

    responseLength = ((data[offset++] & 0xff) << 8);
    responseLength |= (data[offset++] & 0xff);

    if (data.length < 7 + responseLength) {
      return null;
    }

    int blockSize = (responseLength > HID_BUFFER_SIZE - 7 ? HID_BUFFER_SIZE - 7 : responseLength);
    response.write(data, offset, blockSize);
    offset += blockSize;

    while (response.size() != responseLength) {
      sequenceIdx++;

      if (offset == data.length) {
        return null;
      }

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

      blockSize = (responseLength - response.size() > HID_BUFFER_SIZE - 5 ? HID_BUFFER_SIZE - 5 : responseLength - response.size());
      if (blockSize > data.length - offset) {
        return null;
      }
      response.write(data, offset, blockSize);
      offset += blockSize;
    }

    return response.toByteArray();
  }

  private byte[] wrapCommandAPDU(byte[] command) {
    ByteArrayOutputStream output = new ByteArrayOutputStream();

    int sequenceIdx = 0;
    int offset = 0;
    output.write(LEDGER_DEFAULT_CHANNEL >> 8);
    output.write(LEDGER_DEFAULT_CHANNEL);
    output.write(TAG_APDU);
    output.write(sequenceIdx >> 8);
    output.write(sequenceIdx);
    sequenceIdx++;
    output.write(command.length >> 8);
    output.write(command.length);
    int blockSize = (command.length > HID_BUFFER_SIZE - 7 ? HID_BUFFER_SIZE - 7 : command.length);
    output.write(command, offset, blockSize);
    offset += blockSize;

    while (offset != command.length) {
      output.write(LEDGER_DEFAULT_CHANNEL >> 8);
      output.write(LEDGER_DEFAULT_CHANNEL);
      output.write(TAG_APDU);
      output.write(sequenceIdx >> 8);
      output.write(sequenceIdx);
      sequenceIdx++;
      blockSize = (command.length - offset > HID_BUFFER_SIZE - 5 ? HID_BUFFER_SIZE - 5 : command.length - offset);
      output.write(command, offset, blockSize);
      offset += blockSize;
    }

    if ((output.size() % HID_BUFFER_SIZE) != 0) {
      byte[] padding = new byte[HID_BUFFER_SIZE - (output.size() % HID_BUFFER_SIZE)];
      output.write(padding, 0, padding.length);
    }

    return output.toByteArray();
  }

  @Override
  public boolean isConnected() {
    return hidDevice.isOpen();
  }
}
