package im.status.keycard.io;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class LedgerUtil {
  private static final int LEDGER_DEFAULT_CHANNEL = 1;
  private static final int TAG_APDU = 0x05;

  private LedgerUtil() {}

  public interface Callback {
    void write(byte[] chunk) throws IOException;
    void read(byte[] chunk) throws IOException;
  }

  public static APDUResponse send(APDUCommand cmd, int segmentSize, boolean channelInfo, LedgerUtil.Callback cb) throws IOException {
    int offset = 0;

    byte[] command = LedgerUtil.wrapCommandAPDU(cmd.serialize(), segmentSize, channelInfo);
    byte[] chunk = new byte[segmentSize];

    while(offset != command.length) {
      System.arraycopy(command, offset, chunk, 0, segmentSize);
      cb.write(chunk);
      offset += segmentSize;
    }

    ByteArrayOutputStream response = new ByteArrayOutputStream();
    byte[] responseData = null;

    while ((responseData = LedgerUtil.unwrapResponseAPDU(response.toByteArray(), segmentSize, channelInfo)) == null) {
      cb.read(chunk);
      response.write(chunk, 0, segmentSize);
    }

    return new APDUResponse(responseData);
  }

  private static byte[] unwrapResponseAPDU(byte[] data, int segmentSize, boolean channelInfo) throws IOException {
    if ((data == null) || (data.length < 7 + 5)) {
      return null;
    }

    int sequenceIdx = 0;
    int offset = checkResponseHeader(data, 0, sequenceIdx, channelInfo);

    int  responseLength = ((data[offset++] & 0xff) << 8);
    responseLength |= (data[offset++] & 0xff);

    if (data.length < 7 + responseLength) {
      return null;
    }

    ByteArrayOutputStream response = new ByteArrayOutputStream();

    int blockSize = (responseLength > segmentSize - 7 ? segmentSize - 7 : responseLength);
    response.write(data, offset, blockSize);
    offset += blockSize;

    while (response.size() != responseLength) {
      sequenceIdx++;

      if (offset == data.length) {
        return null;
      }

      offset = checkResponseHeader(data, offset, sequenceIdx, channelInfo);

      blockSize = (responseLength - response.size() > segmentSize - 5 ? segmentSize - 5 : responseLength - response.size());
      if (blockSize > data.length - offset) {
        return null;
      }
      response.write(data, offset, blockSize);
      offset += blockSize;
    }

    return response.toByteArray();
  }

  private static int checkResponseHeader(byte[] data, int offset, int sequenceIdx, boolean channelInfo) throws IOException {
    if (channelInfo) {
      if (data[offset++] != (LEDGER_DEFAULT_CHANNEL >> 8)) {
        throw new IOException("Invalid channel");
      }

      if (data[offset++] != (LEDGER_DEFAULT_CHANNEL & 0xff)) {
        throw new IOException("Invalid channel");
      }
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

  private static byte[] wrapCommandAPDU(byte[] command, int segmentSize, boolean channelInfo) {
    ByteArrayOutputStream output = new ByteArrayOutputStream();

    int sequenceIdx = 0;
    int offset = 0;
    writeCommandHeader(output, sequenceIdx, channelInfo);
    sequenceIdx++;

    output.write(command.length >> 8);
    output.write(command.length);
    int blockSize = (command.length > (segmentSize - 7) ? (segmentSize - 7) : command.length);
    output.write(command, offset, blockSize);
    offset += blockSize;

    while (offset != command.length) {
      writeCommandHeader(output, sequenceIdx, channelInfo);
      sequenceIdx++;

      blockSize = ((command.length - offset) > (segmentSize - 5) ? (segmentSize - 5) : (command.length - offset));
      output.write(command, offset, blockSize);
      offset += blockSize;
    }

    if ((output.size() % segmentSize) != 0) {
      byte[] padding = new byte[segmentSize - (output.size() % segmentSize)];
      output.write(padding, 0, padding.length);
    }

    return output.toByteArray();
  }

  private static void writeCommandHeader(ByteArrayOutputStream output, int sequenceIdx, boolean channelInfo) {
    if (channelInfo) {
      output.write(LEDGER_DEFAULT_CHANNEL >> 8);
      output.write(LEDGER_DEFAULT_CHANNEL);
    }

    output.write(TAG_APDU);
    output.write(sequenceIdx >> 8);
    output.write(sequenceIdx);
  }
}
