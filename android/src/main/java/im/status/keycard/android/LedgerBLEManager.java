package im.status.keycard.android;

import android.app.Activity;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothManager;
import android.content.Context;
import android.content.Intent;

import java.util.UUID;

public class LedgerBLEManager {
  private static final int REQUEST_ENABLE_BT = 1;

  final private BluetoothAdapter bluetoothAdapter;
  final private Activity activity;

  public LedgerBLEManager(Activity context) {
    this.activity = context;
    final BluetoothManager bluetoothManager = (BluetoothManager) context.getSystemService(Context.BLUETOOTH_SERVICE);
    this.bluetoothAdapter = bluetoothManager.getAdapter();
  }

  public void ensureBLEEnable() {
    if (!bluetoothAdapter.isEnabled()) {
      Intent enableBtIntent = new Intent(BluetoothAdapter.ACTION_REQUEST_ENABLE);
      activity.startActivityForResult(enableBtIntent, REQUEST_ENABLE_BT);
    }
  }

  public void startScan() {
    bluetoothAdapter.startLeScan(new UUID[] { LedgerBLEChannel.LEDGER_UUID}, null);
  }

  public void stopScan() {
    bluetoothAdapter.stopLeScan(null);
  }
}
