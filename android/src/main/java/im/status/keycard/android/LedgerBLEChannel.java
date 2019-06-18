package im.status.keycard.android;

import android.bluetooth.*;
import android.content.Context;
import im.status.keycard.io.APDUCommand;
import im.status.keycard.io.APDUResponse;
import im.status.keycard.io.CardChannel;
import im.status.keycard.io.LedgerUtil;

import java.io.IOException;
import java.util.UUID;

public class LedgerBLEChannel implements CardChannel {
  final public static UUID LEDGER_UUID = UUID.fromString("13D63400-2C97-0004-0000-4C6564676572");
  final public static UUID LEDGER_REQ_UUID = UUID.fromString("13D63400-2C97-0004-0002-4C6564676572");
  final public static UUID LEDGER_RSP_UUID = UUID.fromString("13D63400-2C97-0004-0001-4C6564676572");

  final private Context context;
  final private BluetoothGatt bluetoothGatt;
  private BluetoothGattCharacteristic reqChar;
  private boolean connected;
  private int mtuSize;

  public LedgerBLEChannel(Context context, BluetoothDevice device) {
    this.context = context;
    this.connected = false;
    this.mtuSize = 20;

    this.bluetoothGatt = device.connectGatt(context, false, new BluetoothGattCallback() {
      @Override
      public void onConnectionStateChange(BluetoothGatt gatt, int status, int newState) {
        connected = newState == BluetoothProfile.STATE_CONNECTED;

        if (connected) {
          bluetoothGatt.discoverServices();
        }
      }

      @Override
      public void onServicesDiscovered(BluetoothGatt gatt, int status) {
        BluetoothGattService service = bluetoothGatt.getService(LEDGER_UUID);

        if (service == null) {
          bluetoothGatt.disconnect();
          connected = false;
          return;
        }

        reqChar = service.getCharacteristic(LEDGER_REQ_UUID);
        BluetoothGattCharacteristic rsp = service.getCharacteristic(LEDGER_RSP_UUID);
        bluetoothGatt.setCharacteristicNotification(rsp, true);
        reqChar.setValue(new byte[] { 0x08, 0x00, 0x00, 0x00, 0x00});
        bluetoothGatt.writeCharacteristic(reqChar);
      }

      @Override
      public void onCharacteristicWrite(BluetoothGatt gatt, BluetoothGattCharacteristic characteristic, int status) {
      }

      @Override
      public void onCharacteristicChanged(BluetoothGatt gatt, BluetoothGattCharacteristic characteristic) {
        byte[] rsp = characteristic.getValue();
        if (rsp[0] == 0x08) {
          mtuSize = rsp[5];
        }
      }
    });
  }

  @Override
  public APDUResponse send(APDUCommand cmd) throws IOException {
    return LedgerUtil.send(cmd, mtuSize, false, new LedgerUtil.Callback() {
      @Override
      public void write(byte[] chunk) throws IOException {

      }

      @Override
      public void read(byte[] chunk) throws IOException {

      }
    });
  }

  @Override
  public boolean isConnected() {
    return connected;
  }

  @Override
  public int pairingPasswordPBKDF2IterationCount() {
    return 10;
  }

  public void close() {
    bluetoothGatt.close();
  }

  @Override
  protected void finalize() throws Throwable {
    close();
    super.finalize();
  }
}
