package im.status.keycard.desktop;

import im.status.keycard.globalplatform.Crypto;
import im.status.keycard.io.CardListener;
import org.hid4java.*;
import org.hid4java.event.HidServicesEvent;

public class LedgerUSBManager implements HidServicesListener {
  static {
    Crypto.addBouncyCastleProvider();
  }

  private static final int VID = 0x2c97;
  private static final int[] PIDS = { 0x0001, 0x0004 };

  private static final int SCAN_INTERVAL_MS = 500;
  private static final int PAUSE_INTERVAL_MS = 5000;

  private HidServices hidServices;
  private CardListener listener;

  public LedgerUSBManager(CardListener listener) {
    this.listener = listener;

    HidServicesSpecification hidServicesSpecification = new HidServicesSpecification();
    hidServicesSpecification.setAutoShutdown(true);
    hidServicesSpecification.setScanInterval(SCAN_INTERVAL_MS);
    hidServicesSpecification.setPauseInterval(PAUSE_INTERVAL_MS);
    hidServicesSpecification.setScanMode(ScanMode.SCAN_AT_FIXED_INTERVAL_WITH_PAUSE_AFTER_WRITE);

    hidServices = HidManager.getHidServices(hidServicesSpecification);
    hidServices.addHidServicesListener(this);
  }

  public void start() {
    hidServices.start();

    for (int pid : PIDS) {
      HidDevice hidDevice = hidServices.getHidDevice(VID, pid, null);

      if (hidDevice != null) {
        listener.onConnected(new LedgerUSBChannel(hidDevice));
        break;
      }
    }
  }

  public void stop() {
    hidServices.shutdown();
  }

  @Override
  public void hidDeviceAttached(HidServicesEvent event) {
    HidDevice hidDevice = event.getHidDevice();

    if (isLedger(hidDevice)) {
      listener.onConnected(new LedgerUSBChannel(hidDevice));
    }

  }

  @Override
  public void hidDeviceDetached(HidServicesEvent event) {
    hidFailure(event);
  }

  @Override
  public void hidFailure(HidServicesEvent event) {
    if (isLedger(event.getHidDevice())) {
      listener.onDisconnected();
    }
  }

  private boolean isLedger(HidDevice hidDevice) {
    for (int pid : PIDS) {
      if (hidDevice.isVidPidSerial(VID, pid, null)) {
        return true;
      }
    }

    return false;
  }
}
