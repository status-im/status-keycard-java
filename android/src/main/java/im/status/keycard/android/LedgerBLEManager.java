package im.status.keycard.android;

import android.app.Activity;
import android.bluetooth.*;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import im.status.keycard.globalplatform.Crypto;
import im.status.keycard.io.CardListener;

import java.util.UUID;

public class LedgerBLEManager {
  private static final int REQUEST_ENABLE_BT = 1;

  final private BluetoothAdapter bluetoothAdapter;
  final private Activity activity;
  private CardListener cardListener;

  static {
    Crypto.addBouncyCastleProvider();
  }

  public LedgerBLEManager(Activity context) {
    this.activity = context;
    final BluetoothManager bluetoothManager = (BluetoothManager) context.getSystemService(Context.BLUETOOTH_SERVICE);
    this.bluetoothAdapter = bluetoothManager.getAdapter();
  }

  public void ensureBLEEnabled() {
    if (!bluetoothAdapter.isEnabled()) {
      Intent enableBtIntent = new Intent(BluetoothAdapter.ACTION_REQUEST_ENABLE);
      activity.startActivityForResult(enableBtIntent, REQUEST_ENABLE_BT);
    }
  }

  public void startScan(BluetoothAdapter.LeScanCallback cb) {
    bluetoothAdapter.startLeScan(new UUID[] { LedgerBLEChannel.LEDGER_UUID}, cb);
  }

  public void stopScan(BluetoothAdapter.LeScanCallback cb) {
    bluetoothAdapter.stopLeScan(cb);
  }

  public void connectDevice(BluetoothDevice device) {
    if (device.getBondState() != BluetoothDevice.BOND_BONDED) {
      final IntentFilter filter = new IntentFilter(BluetoothDevice.ACTION_BOND_STATE_CHANGED);
      activity.registerReceiver(new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
          final BluetoothDevice d = intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE);
          final int bondState = intent.getIntExtra(BluetoothDevice.EXTRA_BOND_STATE, -1);

          if (!d.getAddress().equals(device.getAddress())) {
            return;
          }

          if (bondState == BluetoothDevice.BOND_BONDED) {
            activity.unregisterReceiver(this);
            // connect/disconnect to make bond permanent
            device.connectGatt(activity, false, new BluetoothGattCallback() {
              @Override
              public void onConnectionStateChange(BluetoothGatt gatt, int status, int newState) {
                if (newState == BluetoothGatt.STATE_CONNECTED) {
                  gatt.disconnect();
                  onConnected(device);
                }
              }
            });
          }
        }
      }, filter);

      device.createBond();
    } else {
      onConnected(device);
    }
  }

  private void onConnected(BluetoothDevice device) {
    if (cardListener != null) {
      new LedgerBLEChannel(activity, device, cardListener);
    }
  }

  public void setCardListener(CardListener cardListener) {
    this.cardListener = cardListener;
  }
}
