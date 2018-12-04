package im.status.keycard.wallet;

import org.spongycastle.asn1.x9.X9ECParameters;
import org.spongycastle.asn1.x9.X9IntegerConverter;
import org.spongycastle.crypto.ec.CustomNamedCurves;
import org.spongycastle.crypto.params.ECDomainParameters;
import org.spongycastle.math.ec.ECAlgorithms;
import org.spongycastle.math.ec.ECPoint;
import org.spongycastle.math.ec.FixedPointUtil;
import org.spongycastle.math.ec.custom.sec.SecP256K1Curve;

import java.math.BigInteger;
import java.util.Arrays;

/**
 * Signature with recoverable public key.
 */
public class RecoverableSignature {
  private byte[] publicKey;
  private int recId;
  private byte[] r;
  private byte[] s;

  public static final byte TLV_SIGNATURE_TEMPLATE = (byte) 0xA0;
  public static final byte TLV_ECDSA_TEMPLATE = (byte) 0x30;

  private static final X9ECParameters CURVE_PARAMS = CustomNamedCurves.getByName("secp256k1");
  static final ECDomainParameters CURVE;

  static {
    FixedPointUtil.precompute(CURVE_PARAMS.getG(), 6);
    CURVE = new ECDomainParameters(CURVE_PARAMS.getCurve(), CURVE_PARAMS.getG(), CURVE_PARAMS.getN(), CURVE_PARAMS.getH());
  }

  /**
   * Parses a signature from the card and calculates the recovery ID.
   *
   * @param hash the message being signed
   * @param tlvData the signature as returned from the card
   */
  public RecoverableSignature(byte[] hash, byte[] tlvData) {
    TinyBERTLV tlv = new TinyBERTLV(tlvData);
    tlv.enterConstructed(TLV_SIGNATURE_TEMPLATE);
    publicKey = tlv.readPrimitive(ApplicationInfo.TLV_PUB_KEY);
    tlv.enterConstructed(TLV_ECDSA_TEMPLATE);
    r = tlv.readPrimitive(TinyBERTLV.TLV_INT);
    s = tlv.readPrimitive(TinyBERTLV.TLV_INT);

    recId = -1;

    for (int i = 0; i < 4; i++) {
      byte[] candidate = recoverFromSignature(i, new BigInteger(1, hash), new BigInteger(1, r), new BigInteger(1, s));

      if (Arrays.equals(candidate, publicKey)) {
        recId = i;
        break;
      }
    }

    if (recId == -1) {
      throw new IllegalArgumentException("Unrecoverable signature, cannot find recId");
    }
  }

  /**
   * The public key associated to this signature.
   *
   * @return the public key associated to this signature
   */
  public byte[] getPublicKey() {
    return publicKey;
  }

  /**
   * The recovery ID
   *
   * @return recovery ID
   */
  public int getRecId() {
    return recId;
  }

  /**
   * The R value.
   *
   * @return r
   */
  public byte[] getR() {
    return r;
  }

  /**
   * The S value
   * @return s
   */
  public byte[] getS() {
    return s;
  }

  private static byte[] recoverFromSignature(int recId, BigInteger e, BigInteger r, BigInteger s) {
    BigInteger n = CURVE.getN();
    BigInteger i = BigInteger.valueOf((long) recId / 2);
    BigInteger x = r.add(i.multiply(n));
    BigInteger prime = SecP256K1Curve.q;

    if (x.compareTo(prime) >= 0) {
      return null;
    }

    ECPoint R = decompressKey(x, (recId & 1) == 1);

    if (!R.multiply(n).isInfinity()) {
      return null;
    }

    BigInteger eInv = BigInteger.ZERO.subtract(e).mod(n);
    BigInteger rInv = r.modInverse(n);
    BigInteger srInv = rInv.multiply(s).mod(n);
    BigInteger eInvrInv = rInv.multiply(eInv).mod(n);
    ECPoint q = ECAlgorithms.sumOfTwoMultiplies(CURVE.getG(), eInvrInv, R, srInv);
    return q.getEncoded(false);
  }

  private static ECPoint decompressKey(BigInteger xBN, boolean yBit) {
    X9IntegerConverter x9 = new X9IntegerConverter();
    byte[] compEnc = x9.integerToBytes(xBN, 1 + x9.getByteLength(CURVE.getCurve()));
    compEnc[0] = (byte)(yBit ? 0x03 : 0x02);
    return CURVE.getCurve().decodePoint(compEnc);
  }
}
