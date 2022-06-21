package im.status.keycard.applet;

import java.io.ByteArrayOutputStream;
import java.nio.charset.Charset;
import java.util.SortedSet;
import java.util.TreeSet;

public class Metadata {
  private String cardName;
  private SortedSet<Long> wallets;
  
  public static Metadata fromData(byte[] data) {
    int version = (data[0] & 0xe0) >> 5;

    if (version != 1) {
      throw new RuntimeException("Invalid version");
    }

    int namelen = (data[0] & 0x1f);
    int off = 1;

    String cardName = new String(data, off, namelen, Charset.forName("US-ASCII"));
    off += namelen;

    SortedSet<Long> set = new TreeSet<>();

    while(off < data.length) {
      int[] start = TinyBERTLV.readNum(data, off);
      int[] count = TinyBERTLV.readNum(data, start[1]);
      off = count[1];
      long s = start[0] & 0xffffffffl;
      buildRange(set, s, (s + count[0]));
    }

    return new Metadata(cardName, set);
  }

  private static void buildRange(SortedSet<Long> set, long start, long end) {
    for (long i = start; i <= end; i++) {
      set.add(i);
    }
  }

  Metadata(String cardName, SortedSet<Long> wallets) {
    this.cardName = cardName;
    this.wallets = wallets;
  }

  public Metadata(String cardName) {
    this(cardName, new TreeSet<>());
  }

  public String getCardName() {
    return cardName;
  }

  public void setCardName(String cardName) {
    if (cardName.length() > 20) {
      throw new IllegalArgumentException("card name too long");
    }
    
    this.cardName = cardName;
  }

  public SortedSet<Long> getWallets() {
    return wallets;
  }

  public void addWallet(long w) {
    this.wallets.add(w);
  }

  public void removeWallet(long w) {
    this.wallets.remove(w);
  }

  public byte[] toByteArray() {
    ByteArrayOutputStream os = new ByteArrayOutputStream();
    byte[] name = this.cardName.getBytes(Charset.forName("US-ASCII"));
    os.write(0x20 | name.length);
    os.write(name, 0, name.length);

    if (wallets.isEmpty()) {
      return os.toByteArray();
    }

    long start = wallets.first();
    int len = 0;

    for (Long w : wallets.tailSet(start + 1)) {
      if (w == (start + len + 1)) {
        len++;
      } else {
        TinyBERTLV.writeNum(os, (int) start);
        TinyBERTLV.writeNum(os, len);
        len = 0;
        start = w;
      }
    }

    TinyBERTLV.writeNum(os, (int) start);
    TinyBERTLV.writeNum(os, len);

    return os.toByteArray();
  }
}
