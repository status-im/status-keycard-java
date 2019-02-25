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
  private static final int PID = 0x0001;

  private HidServices hidServices;
  private CardListener listener;

  public LedgerUSBManager(CardListener listener) {
    this.listener = listener;

    HidServicesSpecification hidServicesSpecification = new HidServicesSpecification();
    hidServicesSpecification.setAutoShutdown(true);
    hidServicesSpecification.setScanInterval(500);
    hidServicesSpecification.setPauseInterval(5000);
    hidServicesSpecification.setScanMode(ScanMode.SCAN_AT_FIXED_INTERVAL_WITH_PAUSE_AFTER_WRITE);

    hidServices = HidManager.getHidServices(hidServicesSpecification);
    hidServices.addHidServicesListener(this);
  }

  public void start() {
    hidServices.start();

    HidDevice hidDevice = hidServices.getHidDevice(VID, PID, null);

    if (hidDevice != null) {
      listener.onConnected(new LedgerUSBChannel(hidDevice));
    }
  }

  public void stop() {
    hidServices.shutdown();
  }

  @Override
  public void hidDeviceAttached(HidServicesEvent event) {
    HidDevice hidDevice = event.getHidDevice();

    if (hidDevice.isVidPidSerial(VID, PID, null)) {
      listener.onConnected(new LedgerUSBChannel(hidDevice));
    }

  }

  @Override
  public void hidDeviceDetached(HidServicesEvent event) {
    hidFailure(event);
  }

  @Override
  public void hidFailure(HidServicesEvent event) {
    HidDevice hidDevice = event.getHidDevice();

    if (hidDevice.isVidPidSerial(VID, PID, null)) {
      listener.onDisconnected();
    }
  }
}
