package im.status.keycard.android;

import android.bluetooth.*;
import android.content.Context;
import im.status.keycard.io.*;

import java.io.IOException;
import java.util.UUID;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;

public class LedgerBLEChannel implements CardChannel {
  final public static UUID LEDGER_UUID = UUID.fromString("13D63400-2C97-0004-0000-4C6564676572");
  final public static UUID LEDGER_REQ_UUID = UUID.fromString("13D63400-2C97-0004-0002-4C6564676572");
  final public static UUID LEDGER_RSP_UUID = UUID.fromString("13D63400-2C97-0004-0001-4C6564676572");

  final private static int BLE_WRITE_FAILED = -1;
  final private static int BLE_WRITE_STARTED = 0;
  final private static int BLE_WRITE_FINISHED = 1;

  final private static int BLE_TIMEOUT = 2000;


  final private BluetoothGatt bluetoothGatt;
  private BluetoothGattCharacteristic reqChar;
  private boolean connected;
  private int mtuSize;
  private int writeStatus;
  private LinkedBlockingQueue<byte[]> readQueue;

  public LedgerBLEChannel(Context context, BluetoothDevice device, CardListener listener) {
    this.connected = false;
    this.mtuSize = 20;
    this.readQueue = new LinkedBlockingQueue<>();
    this.writeStatus = BLE_WRITE_FINISHED;
    final CardChannel channel = this;

    this.bluetoothGatt = device.connectGatt(context, false, new BluetoothGattCallback() {
      @Override
      public void onConnectionStateChange(BluetoothGatt gatt, int status, int newState) {
        if (connected  == (newState ==  BluetoothProfile.STATE_CONNECTED)) {
          return;
        }

        connected = newState == BluetoothProfile.STATE_CONNECTED;

        if (connected) {
          bluetoothGatt.discoverServices();
        } else {
          (new Thread() {
            @Override
            public void run() {
              listener.onDisconnected();
            }
          }).start();
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

        BluetoothGattDescriptor rspDesc = rsp.getDescriptors().get(0);
        rspDesc.setValue(BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE);
        gatt.writeDescriptor(rspDesc);
      }

      @Override
      public void onCharacteristicWrite(BluetoothGatt gatt, BluetoothGattCharacteristic characteristic, int status) {
        writeStatus = status == BluetoothGatt.GATT_SUCCESS ? BLE_WRITE_FINISHED : BLE_WRITE_FAILED;
      }

      @Override
      public void onDescriptorWrite(BluetoothGatt gatt, BluetoothGattDescriptor descriptor, int status) {
        reqChar.setValue(new byte[] { 0x08, 0x00, 0x00, 0x00, 0x00});
        bluetoothGatt.writeCharacteristic(reqChar);
      }

      @Override
      public void onCharacteristicChanged(BluetoothGatt gatt, BluetoothGattCharacteristic characteristic) {
        byte[] rsp = characteristic.getValue();

        if (rsp[0] == 0x08) {
          mtuSize = rsp[5];
          (new Thread() {
            @Override
            public void run() {
              listener.onConnected(channel);
            }
          }).start();
          return;
        }

        readQueue.offer(rsp);
      }
    });
  }

  @Override
  public APDUResponse send(APDUCommand cmd) throws IOException {
    return LedgerUtil.send(cmd, mtuSize, false, new LedgerUtil.Callback() {
      @Override
      public void write(byte[] chunk) throws IOException {
        writeStatus = BLE_WRITE_STARTED;
        reqChar.setValue(chunk);
        bluetoothGatt.writeCharacteristic(reqChar);

        long timeout = 0;
        while(writeStatus == BLE_WRITE_STARTED || timeout >= BLE_TIMEOUT) {
          try {
            Thread.sleep(10);
            timeout += 10;
          } catch (InterruptedException e) {
            throw new IOException("write interrupted");
          }
        }

        if (writeStatus != BLE_WRITE_FINISHED) {
          throw new IOException("write operation failed");
        }
      }

      @Override
      public void read(byte[] chunk) throws IOException {
        try {
          byte[] data = readQueue.poll(BLE_TIMEOUT, TimeUnit.MILLISECONDS);

          if (data == null) {
            throw new IOException("read timeout");
          }

          System.arraycopy(data, 0, chunk, 0, Math.min(data.length, chunk.length));
        } catch (InterruptedException e) {
          throw new IOException("read timeout");
        }
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
