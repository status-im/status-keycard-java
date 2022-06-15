package im.status.keycard.applet;

import java.math.BigInteger;
import java.security.DigestException;
import java.security.MessageDigest;
import java.util.Arrays;

public class BLS {
  public static byte[] hash(byte[] msg) {
    Fp[][] u = hashToField(msg, 2);
    PointG2 q0 = isogenyMapG2(mapToCurveSimpleSWU9mod16(new Fp2(u[0][0], u[0][1])));
    PointG2 q1 = isogenyMapG2(mapToCurveSimpleSWU9mod16(new Fp2(u[1][0], u[1][1])));
    PointG2 r = q0.add(q1).clearCofactor();
    return r.toByteArray(false);
  }

  public static byte[] compress(byte[] g2) {
    return new PointG2(g2).toByteArray(true);
  }

  private BLS() {}

  final static byte DST[] = {
    (byte) 0x42, (byte) 0x4C, (byte) 0x53, (byte) 0x5F, (byte) 0x53, (byte) 0x49, (byte) 0x47, (byte) 0x5F,
    (byte) 0x42, (byte) 0x4C, (byte) 0x53, (byte) 0x31, (byte) 0x32, (byte) 0x33, (byte) 0x38, (byte) 0x31,
    (byte) 0x47, (byte) 0x32, (byte) 0x5F, (byte) 0x58, (byte) 0x4D, (byte) 0x44, (byte) 0x3A, (byte) 0x53,
    (byte) 0x48, (byte) 0x41, (byte) 0x2D, (byte) 0x32, (byte) 0x35, (byte) 0x36, (byte) 0x5F, (byte) 0x53,
    (byte) 0x53, (byte) 0x57, (byte) 0x55, (byte) 0x5F, (byte) 0x52, (byte) 0x4F, (byte) 0x5F, (byte) 0x4E,
    (byte) 0x55, (byte) 0x4C, (byte) 0x5F, (byte) 0x2B,
  };

  final private static int L = 64;
  final private static int M = 2;
  final private static int SHA256_DIGEST_SIZE = 32;

  final private static BigInteger P = new BigInteger("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab", 16);
  final private static BigInteger P_MINUS_9_DIV_16 = P.pow(2).subtract(BigInteger.valueOf(9)).divide(BigInteger.valueOf(16));
  final private static BigInteger CURVE_X = new BigInteger("d201000000010000", 16);

  final private static Fp rv1 = new Fp("6af0e0437ff400b6831e36d6bd17ffe48395dabc2d3435e77f76e17009241c5ee67992f72ec05f4c81084fbede3cc09");
  final private static Fp ev1 = new Fp("699be3b8c6870965e5bf892ad5d2cc7b0e85a117402dfd83b7f4a947e02d978498255a2aaec0ac627b5afbdf1bf1c90");
  final private static Fp ev2 = new Fp("8157cd83046453f5dd0972b6e3949e4288020b5b8a9cc99ca07e27089a2ce2436d965026adad3ef7baba37f2183e9b5");
  final private static Fp ev3 = new Fp("ab1c2ffdd6c253ca155231eb3e71ba044fd562f6f72bc5bad5ec46a0b7a3b0247cf08ce6c6317f40edbc653a72dee17");
  final private static Fp ev4 = new Fp("aa404866706722864480885d68ad0ccac1967c7544b447873cc37e0181271e006df72162a3d3e0287bf597fbf7f8fc1");

  final private static Fp PSI2_C1 = new Fp("1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaac");

  final private static Fp2[] xnum = new Fp2[] {
    new Fp2(new Fp("5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6"),
            new Fp("5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6")),
    new Fp2(Fp.ZERO,
            new Fp("11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71a")),
    new Fp2(new Fp("11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71e"),
            new Fp("8ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38d")),
    new Fp2(new Fp("171d6541fa38ccfaed6dea691f5fb614cb14b4e7f4e810aa22d6108f142b85757098e38d0f671c7188e2aaaaaaaa5ed1"),
            Fp.ZERO),    
  };

  final private static Fp2[] xden = new Fp2[] {
    new Fp2(Fp.ZERO,
            new Fp("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa63")),
    new Fp2(new Fp(0xc),
            new Fp("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa9f")),
    Fp2.ONE,
    Fp2.ZERO,    
  };  

  final private static Fp2[] ynum = new Fp2[] {
    new Fp2(new Fp("1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706"),
            new Fp("1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706")),
    new Fp2(Fp.ZERO,
            new Fp("5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97be")),
    new Fp2(new Fp("11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71c"),
            new Fp("8ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38f")),
    new Fp2(new Fp("124c9ad43b6cf79bfbf7043de3811ad0761b0f37a1e26286b0e977c69aa274524e79097a56dc4bd9e1b371c71c718b10"),
            Fp.ZERO),    
  };

  final private static Fp2[] yden = new Fp2[] {
    new Fp2(new Fp("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fb"),
            new Fp("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fb")),
    new Fp2(Fp.ZERO,
            new Fp("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa9d3")),
    new Fp2(new Fp(0x12),
            new Fp("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa99")),
    new Fp2(Fp.ONE, Fp.ZERO),    
  }; 

  final private static Fp2[][] ISOGENY_COEFFICIENTS = new Fp2[][] { xnum, xden, ynum, yden };  

  final private static Fp2[] FP2_ROOTS_OF_UNITY = new Fp2[] {
    Fp2.ONE,
    new Fp2(rv1, rv1.neg()),
    new Fp2(Fp.ZERO, Fp.ONE),
    new Fp2(rv1, rv1),
    new Fp2(Fp.ONE.neg(), Fp.ZERO),
    new Fp2(rv1.neg(), rv1),
    new Fp2(Fp.ZERO, Fp.ONE.neg()),
    new Fp2(rv1.neg(), rv1.neg()),
  };

  final private static Fp2[] FP2_ETAs = new Fp2[] {
    new Fp2(ev1, ev2),
    new Fp2(ev2.neg(), ev1),
    new Fp2(ev3, ev4),
    new Fp2(ev4.neg(), ev3),
  };

  private static byte[] strxor(byte[] b0, byte[] b1, int b1off) {
    byte[] xored = new byte[b0.length];
    for (int i = 0; i < xored.length; i++) {
      xored[i] = (byte) (b0[i] ^ b1[i + b1off]);
    }

    return xored;
  }

  private static byte[] expandMessage(byte[] msg, byte[] DST, int len) {
    MessageDigest md;
    try {
      md = MessageDigest.getInstance("SHA256");
    } catch (Exception e) {
      throw new RuntimeException("SHA256 missing");
    }

    int ell = (len + (SHA256_DIGEST_SIZE - 1)) / SHA256_DIGEST_SIZE;

    md.update(new byte[SHA256_DIGEST_SIZE * 2]);
    md.update(msg);
    md.update(new byte[] { (byte) ((len >> 8) & 0xff), (byte) (len & 0xff), (byte) 0 });
    md.update(DST);
    byte[] b0 = md.digest();
    byte[] b = new byte[ell * SHA256_DIGEST_SIZE];

    for (int i = 0; i < ell; i++) {
      if (i == 0) {
        md.update(b0);
      } else {
        md.update(strxor(b0, b, ((i - 1) * SHA256_DIGEST_SIZE)));
      }

      md.update((byte) (i + 1));
      md.update(DST);

      try {
        md.digest(b, (i * SHA256_DIGEST_SIZE), SHA256_DIGEST_SIZE);
      } catch (DigestException e) {
        throw new RuntimeException("SHA256 error");
      }
    }

    return Arrays.copyOf(b, len);
  }

  private static Fp[][] hashToField(byte[] msg, int count) {
    byte[] uniformBytes = expandMessage(msg, DST, count * M * L);
    Fp[][] u = new Fp[count][M];
    for (int i = 0; i < count; i++) {
      for (int j = 0; j < M; j++) {
        int off = (L * (j + (i * M)));
        u[i][j] = new Fp(Arrays.copyOfRange(uniformBytes, off, off + L));
      }
    }
    return u; 
  }

  private static PointG2 isogenyMapG2(PointG2 point) {
    Fp2[] zPowers = new Fp2[] {point.z, point.z.square(), point.z.pow(3)};
    Fp2[] mapped = new Fp2[] {Fp2.ZERO, Fp2.ZERO, Fp2.ZERO, Fp2.ZERO};

    for (int i = 0; i < ISOGENY_COEFFICIENTS.length; i++) {
      Fp2[] kI = ISOGENY_COEFFICIENTS[i];
      mapped[i] = kI[3];
      Fp2[] arr = new Fp2[] { kI[2], kI[1], kI[0] };
      for (int j = 0; j < arr.length; j++) {
        Fp2 kIJ = arr[j];
        mapped[i] = mapped[i].mul(point.x).add(zPowers[j].mul(kIJ));
      }
  
    }

    mapped[2] = mapped[2].mul(point.y);
    mapped[3] = mapped[3].mul(point.z);
  
    Fp2 z2 = mapped[1].mul(mapped[3]);
    Fp2 x2 = mapped[0].mul(mapped[3]);
    Fp2 y2 = mapped[1].mul(mapped[2]);

    return new PointG2(x2, y2, z2);  
  }

  private static SqrtDivFp2Res sqrtDivFp2(Fp2 u, Fp2 v) {
    Fp2 v7 = v.pow(7);
    Fp2 uv7 = u.mul(v7);
    Fp2 uv15 = uv7.mul(v7.mul(v));
    Fp2 gamma = uv15.pow(P_MINUS_9_DIV_16).mul(uv7);

    for (int i = 0; i < 4; i++) {
      Fp2 candidate = FP2_ROOTS_OF_UNITY[i].mul(gamma);
      if (candidate.square().mul(v).sub(u).isZero()) {
        return new SqrtDivFp2Res(true, candidate);
      }
    }

    return new SqrtDivFp2Res(false, gamma);
  }  

  private static PointG2 mapToCurveSimpleSWU9mod16(Fp2 t) {
    Fp2 iso3a = new Fp2(new Fp(0), new Fp(240));
    Fp2 iso3b = new Fp2(new Fp(1012), new Fp(1012));
    Fp2 iso3z = new Fp2(new Fp(-2), new Fp(-1));
    Fp2 t2 = t.square();
    Fp2 iso3zt2 = iso3z.mul(t2);
    Fp2 ztzt = iso3zt2.add(iso3zt2.square());
    Fp2 denominator = iso3a.mul(ztzt).neg();
    Fp2 numerator = iso3b.mul(ztzt.add(Fp2.ONE));

    if (denominator.isZero()) {
      denominator = iso3z.mul(iso3a);
    }

    Fp2 v = denominator.pow(3);
    Fp2 u = numerator.pow(3)
      .add(iso3a.mul(numerator).mul(denominator.square()))
      .add(iso3b.mul(v));
    
    SqrtDivFp2Res sqrtCandidateOrGamma = sqrtDivFp2(u, v);

    Fp2 y = null;

    if (!sqrtCandidateOrGamma.success) {
      u = iso3zt2.pow(3).mul(u);
      Fp2 sqrtCandidateX1 = sqrtCandidateOrGamma.value.mul(t.pow(3));

      for (int i = 0; i < FP2_ETAs.length; i++) {
        Fp2 etaSqrtCanditate = FP2_ETAs[i].mul(sqrtCandidateX1);
        if (etaSqrtCanditate.square().mul(v).sub(u).isZero()) {
          y = etaSqrtCanditate;
          numerator = numerator.mul(iso3zt2);
          break;
        }
      }
    } else {
      y = sqrtCandidateOrGamma.value;
    }

    if (y == null) {
      throw new RuntimeException("Hash to Curve - Optimized SWU failed");
    }

    if (t.sgn0() != y.sgn0()) {
      y = y.neg();
    }

    y = y.mul(denominator);
    return new PointG2(numerator, y, denominator);
  }

  static class Fp {
    final static Fp ZERO = new Fp(BigInteger.ZERO);
    final static Fp ONE = new Fp(BigInteger.ONE);
    final static int SIZE = 48;

    private BigInteger i;

    Fp(byte[] b) {
      this(new BigInteger(1, b));
    }

    Fp(long i) {
      this(BigInteger.valueOf(i));
    }

    Fp(BigInteger i) {
      this.i = i.mod(P);
    }

    Fp(String hex) {
      this(new BigInteger(hex, 16));
    }

    Fp mul(Fp b) {
      return new Fp(this.i.multiply(b.i));
    }

    Fp add(Fp b) {
      return new Fp(this.i.add(b.i));
    }

    Fp sub(Fp b) {
      return new Fp(this.i.subtract(b.i));
    }

    Fp neg() {
      return new Fp(this.i.negate());
    }

    Fp square() {
      return new Fp(this.i.pow(2));
    }
    
    Fp inv() {
      return new Fp(i.modInverse(P));   
    } 

    boolean isZero() {
      return this.i.signum() == 0;
    }

    void serialize(byte[] out, int off) {
      byte[] encoded = i.toByteArray();
      int padding = SIZE - encoded.length;
      System.arraycopy(encoded, 0, out, off + padding, encoded.length);
    }

    @Override
    public boolean equals(Object o) {
      if (o == this) {
        return true;
      }

      if (!(o instanceof Fp)) {
        return false;
      }

      Fp b = (Fp) o;
      return b.i.equals(this.i); 
    }
  }

  static class Fp2 {
    final static Fp[] FROBENIUS_COEFFICIENTS = new Fp[] {
      Fp.ONE,
      new Fp("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaa")
    };

    final static Fp2 ZERO = new Fp2(Fp.ZERO, Fp.ZERO);
    final static Fp2 ONE = new Fp2(Fp.ONE, Fp.ZERO);

    final static int SIZE = Fp.SIZE * 2;

    private Fp re;
    private Fp im;

    Fp2(Fp re, Fp im) {
      this.re = re;
      this.im = im;
    }

    Fp2(byte[] buf, int off) {
      this(new Fp(Arrays.copyOfRange(buf, off + Fp.SIZE, off + Fp2.SIZE)), new Fp(Arrays.copyOfRange(buf, off, off + Fp.SIZE)));
    }

    int sgn0() {
      boolean sign0 = this.re.i.testBit(0);
      return sign0 || (this.re.isZero() && this.im.i.testBit(0)) ? 1 : 0;
    }

    Fp2 square() {
      Fp a = this.re.add(this.im);
      Fp b = this.re.sub(this.im);
      Fp c = this.re.add(this.re);
      return new Fp2(a.mul(b), c.mul(this.im));
    }

    Fp2 pow(long n) {
      return this.pow(BigInteger.valueOf(n));
    }

    Fp2 pow(BigInteger n) {
      if (n.signum() == 0) return Fp2.ONE;
      if (n.equals(BigInteger.ONE)) return this;

      Fp2 p = Fp2.ONE;
      Fp2 d = this;

      int bitLength = n.bitLength();
      for (int i = 0; i < bitLength; i++) {
        if (n.testBit(i)) {
          p = p.mul(d);
        }

        d = d.square();
      }

      return p;      
    }

    boolean isZero() {
      return this.re.isZero() && this.im.isZero();
    }

    Fp2 mul(Fp2 b) {
      Fp t1 = this.re.mul(b.re);
      Fp t2 = this.im.mul(b.im);
      return new Fp2(t1.sub(t2), this.re.add(this.im).mul(b.re.add(b.im)).sub(t1.add(t2)));
    }

    Fp2 mul(long b) {
      return mul(new Fp(b));
    }

    Fp2 mul(Fp b) {
      return new Fp2(this.re.mul(b), this.im.mul(b));
    }   

    Fp2 add(Fp2 b) {
      return new Fp2(this.re.add(b.re), this.im.add(b.im));
    }

    Fp2 sub(Fp2 b) {
      return new Fp2(this.re.sub(b.re), this.im.sub(b.im));
    }

    Fp2 neg() {
      return new Fp2(this.re.neg(), this.im.neg());
    }  

    Fp2 inv() {
      Fp factor = this.re.square().add(this.im.square()).inv();
      return new Fp2(factor.mul(this.re), factor.mul(this.im.neg()));
    } 

    Fp2 mulByNonresidue() {
      return new Fp2(this.re.sub(this.im), this.re.add(this.im));
    }

    Fp2 frobeniusMap(int power) {
      return new Fp2(this.re, this.im.mul(FROBENIUS_COEFFICIENTS[power % 2]));
    }

    void serialize(byte[] out, int off) {
      this.im.serialize(out, off);
      this.re.serialize(out, Fp.SIZE + off);
    }

    @Override
    public boolean equals(Object o) {
      if (o == this) {
        return true;
      }

      if (!(o instanceof Fp2)) {
        return false;
      }

      Fp2 b = (Fp2) o;
      return b.re.equals(this.re) && b.im.equals(this.im); 
    }
  }

  static class Fp6 {
    final static Fp2[] FROBENIUS_COEFFICIENTS_1 = new Fp2[] {
      Fp2.ONE,
      new Fp2(
        Fp.ZERO,
        new Fp("1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaac")
      ),
      new Fp2(
        new Fp("00000000000000005f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffefffe"),
        Fp.ZERO
      ),
      new Fp2(Fp.ZERO, Fp.ONE),
      new Fp2(
        new Fp("1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaac"),
        Fp.ZERO
      ),
      new Fp2(
        Fp.ZERO,
        new Fp("00000000000000005f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffefffe")
      ),
    };

    final static Fp2[] FROBENIUS_COEFFICIENTS_2 = new Fp2[] {
      Fp2.ONE,
      new Fp2(
        new Fp("1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaad"),
        Fp.ZERO
      ),
      new Fp2(
        new Fp("1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaac"),
        Fp.ZERO
      ),
      new Fp2(
        new Fp("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaa"),
        Fp.ZERO
      ),
      new Fp2(
        new Fp("00000000000000005f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffefffe"),
        Fp.ZERO
      ),
      new Fp2(
        new Fp("00000000000000005f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffeffff"),
        Fp.ZERO
      ),
    };

    final static Fp6 ZERO = new Fp6(Fp2.ZERO, Fp2.ZERO, Fp2.ZERO);
    final static Fp6 ONE = new Fp6(Fp2.ONE, Fp2.ZERO, Fp2.ZERO);

    private Fp2 c0;
    private Fp2 c1;
    private Fp2 c2;

    Fp6(Fp2 c0, Fp2 c1, Fp2 c2) {
      this.c0 = c0;
      this.c1 = c1;
      this.c2 = c2;
    }

    Fp6 add(Fp6 b) {
      return new Fp6(this.c0.add(b.c0), this.c1.add(b.c1), this.c2.add(b.c2));
    }

    Fp6 sub(Fp6 b) {
      return new Fp6(this.c0.sub(b.c0), this.c1.sub(b.c1), this.c2.sub(b.c2));
    }
  
    Fp6 mul(Fp6 b) {
      Fp2 t0 = this.c0.mul(b.c0);
      Fp2 t1 = this.c1.mul(b.c1);
      Fp2 t2 = this.c2.mul(b.c2);
      
      return new Fp6(
        t0.add(this.c1.add(this.c2).mul(b.c1.add(b.c2)).sub(t1.add(t2)).mulByNonresidue()),
        c0.add(c1).mul(b.c0.add(b.c1)).sub(t0.add(t1)).add(t2.mulByNonresidue()),
        t1.add(c0.add(c2).mul(b.c0.add(b.c2)).sub(t0.add(t2)))
      );
    }

    Fp6 mulByNonresidue() {
      return new Fp6(this.c2.mulByNonresidue(), this.c0, this.c1);
    } 
    
    Fp6 mulByFp2(Fp2 b) {
      return new Fp6(this.c0.mul(b), this.c1.mul(b), this.c2.mul(b));
    }
  
    Fp6 square() {
      Fp2 t0 = this.c0.square();
      Fp2 t1 = this.c0.mul(this.c1).mul(2);
      Fp2 t3 = this.c1.mul(this.c2).mul(2);
      Fp2 t4 = this.c2.square();

      return new Fp6(
        t3.mulByNonresidue().add(t0),
        t4.mulByNonresidue().add(t1),
        t1.add(this.c0.sub(this.c1).add(this.c2).square()).add(t3).sub(t0).sub(t4)
      );
    }

    Fp6 neg() {
      return new Fp6(this.c0.neg(), this.c1.neg(), this.c2.neg());
    }  
  
    Fp6 inv() {
      Fp2 t0 = this.c0.square().sub(this.c2.mul(this.c1).mulByNonresidue());
      Fp2 t1 = this.c2.square().mulByNonresidue().sub(this.c0.mul(this.c1));
      Fp2 t2 = this.c1.square().sub(this.c0.mul(this.c2));
      Fp2 t4 = this.c2.mul(t1).add(this.c1.mul(t2)).mulByNonresidue().add(this.c0.mul(t0)).inv();
      return new Fp6(t4.mul(t0), t4.mul(t1), t4.mul(t2));
    }

    Fp6 frobeniusMap(int power) {
      return new Fp6(
        this.c0.frobeniusMap(power),
        this.c1.frobeniusMap(power).mul(FROBENIUS_COEFFICIENTS_1[power % 6]),
        this.c2.frobeniusMap(power).mul(FROBENIUS_COEFFICIENTS_2[power % 6])
      );
    }  
  }

  static class Fp12 {
    final static Fp2[] FROBENIUS_COEFFICIENTS = new Fp2[] {
      Fp2.ONE,
      new Fp2(
        new Fp("1904d3bf02bb0667c231beb4202c0d1f0fd603fd3cbd5f4f7b2443d784bab9c4f67ea53d63e7813d8d0775ed92235fb8"),
        new Fp("00fc3e2b36c4e03288e9e902231f9fb854a14787b6c7b36fec0c8ec971f63c5f282d5ac14d6c7ec22cf78a126ddc4af3")
      ),
      new Fp2(
        new Fp("00000000000000005f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffeffff"),
        Fp.ZERO
      ),
      new Fp2(
        new Fp("135203e60180a68ee2e9c448d77a2cd91c3dedd930b1cf60ef396489f61eb45e304466cf3e67fa0af1ee7b04121bdea2"),
        new Fp("06af0e0437ff400b6831e36d6bd17ffe48395dabc2d3435e77f76e17009241c5ee67992f72ec05f4c81084fbede3cc09")
      ),
      new Fp2(
        new Fp("00000000000000005f19672fdf76ce51ba69c6076a0f77eaddb3a93be6f89688de17d813620a00022e01fffffffefffe"),
        Fp.ZERO
      ),
      new Fp2(
        new Fp("144e4211384586c16bd3ad4afa99cc9170df3560e77982d0db45f3536814f0bd5871c1908bd478cd1ee605167ff82995"),
        new Fp("05b2cfd9013a5fd8df47fa6b48b1e045f39816240c0b8fee8beadf4d8e9c0566c63a3e6e257f87329b18fae980078116")
      ),
      new Fp2(
        new Fp("1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaaa"),
        Fp.ZERO
      ),
      new Fp2(
        new Fp("00fc3e2b36c4e03288e9e902231f9fb854a14787b6c7b36fec0c8ec971f63c5f282d5ac14d6c7ec22cf78a126ddc4af3"),
        new Fp("1904d3bf02bb0667c231beb4202c0d1f0fd603fd3cbd5f4f7b2443d784bab9c4f67ea53d63e7813d8d0775ed92235fb8")
      ),
      new Fp2(
        new Fp("1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaac"),
        Fp.ZERO
      ),
      new Fp2(
        new Fp("06af0e0437ff400b6831e36d6bd17ffe48395dabc2d3435e77f76e17009241c5ee67992f72ec05f4c81084fbede3cc09"),
        new Fp("135203e60180a68ee2e9c448d77a2cd91c3dedd930b1cf60ef396489f61eb45e304466cf3e67fa0af1ee7b04121bdea2")
      ),
      new Fp2(
        new Fp("1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaad"),
        Fp.ZERO
      ),
      new Fp2(
        new Fp("05b2cfd9013a5fd8df47fa6b48b1e045f39816240c0b8fee8beadf4d8e9c0566c63a3e6e257f87329b18fae980078116"),
        new Fp("144e4211384586c16bd3ad4afa99cc9170df3560e77982d0db45f3536814f0bd5871c1908bd478cd1ee605167ff82995")
      ),
    };

    final static Fp12 ZERO = new Fp12(Fp6.ZERO, Fp6.ZERO);
    final static Fp12 ONE = new Fp12(Fp6.ONE, Fp6.ZERO);

    private Fp6 c0;
    private Fp6 c1;

    Fp12(Fp6 c0, Fp6 c1) {
      this.c0 = c0;
      this.c1 = c1;
    }

    Fp12 add(Fp12 b) {
      return new Fp12(this.c0.add(b.c0), this.c1.add(b.c1));
    }

    Fp12 sub(Fp12 b) {
      return new Fp12(this.c0.sub(b.c0), this.c1.sub(b.c1));
    }
  
    Fp12 mul(Fp12 b) {
      Fp6 t1 = this.c0.mul(b.c0);
      Fp6 t2 = this.c1.mul(b.c1);

      return new Fp12(
        t1.add(t2.mulByNonresidue()),
        this.c0.add(this.c1).mul(b.c0.add(b.c1)).sub(t1.add(t2))
      );
    }
  
    Fp12 mulByFp2(Fp2 b) {
      return new Fp12(this.c0.mulByFp2(b), this.c1.mulByFp2(b));
    }
  
    Fp12 square() {
      Fp6 ab = this.c0.mul(this.c1);

      return new Fp12(
        this.c1.mulByNonresidue().add(this.c0).mul(this.c0.add(this.c1)).sub(ab).sub(ab.mulByNonresidue()),
        ab.add(ab)
      );
    }
  
    Fp12 inv() {
      Fp6 t = this.c0.square().sub(this.c1.square().mulByNonresidue()).inv();
      return new Fp12(this.c0.mul(t), this.c1.mul(t).neg());
    }
  
    Fp12 frobeniusMap(int power) {
      Fp6 r0 = this.c0.frobeniusMap(power);
      Fp6 r1 = this.c1.frobeniusMap(power);
      Fp2 coeff = FROBENIUS_COEFFICIENTS[power % 12];
      return new Fp12(
        r0,
        new Fp6(r1.c0.mul(coeff), r1.c1.mul(coeff), r1.c2.mul(coeff))
      );
    }
  }

  static class SqrtDivFp2Res {
    private boolean success;
    private Fp2 value;

    SqrtDivFp2Res(boolean success, Fp2 value) {
      this.success = success;
      this.value = value;
    }
  }

  static class PointG2 {
    final static Fp6 UT_ROOT = new Fp6(Fp2.ZERO, Fp2.ONE, Fp2.ZERO);
    final static Fp12 WSQ = new Fp12(UT_ROOT, Fp6.ZERO);
    final static Fp12 WCU = new Fp12(Fp6.ZERO, UT_ROOT);
    final static Fp12 WSQ_INV = WSQ.inv();
    final static Fp12 WCU_INV = WCU.inv();

    final static PointG2 ZERO = new PointG2(Fp2.ONE, Fp2.ONE, Fp2.ZERO);

    private Fp2 x;
    private Fp2 y;
    private Fp2 z;

    PointG2(Fp2 x, Fp2 y, Fp2 z) {
      this.x = x;
      this.y = y;
      this.z = z;
    }

    PointG2(byte[] buf) {
      this.x = new Fp2(buf, 0);
      this.y = new Fp2(buf, Fp2.SIZE);
      this.z = Fp2.ONE;
    }

    PointG2 add(PointG2 b) {
      if (this.isZero()) {
        return b;
      } else if (b.isZero()) {
        return this;
      }

      Fp2 x1 = this.x;
      Fp2 y1 = this.y;
      Fp2 z1 = this.z;
      Fp2 x2 = b.x;
      Fp2 y2 = b.y;
      Fp2 z2 = b.z;
      Fp2 u1 = y2.mul(z1);
      Fp2 u2 = y1.mul(z2);
      Fp2 v1 = x2.mul(z1);
      Fp2 v2 = x1.mul(z2);
      if (v1.equals(v2) && u1.equals(u2)) {
        return this.doubleP();
      }

      if (v1.equals(v2)) {
        return PointG2.ZERO;
      }

      Fp2 u = u1.sub(u2);
      Fp2 v = v1.sub(v2);
      Fp2 vv = v.square();
      Fp2 vvv = vv.mul(v);
      Fp2 v2vv = v2.mul(vv);
      Fp2 w = z1.mul(z2);
      Fp2 a = u.square().mul(w).sub(vvv).sub(v2vv.add(v2vv));
      Fp2 x3 = v.mul(a);
      Fp2 y3 = u.mul(v2vv.sub(a)).sub(vvv.mul(u2));
      Fp2 z3 = vvv.mul(w);
      return new PointG2(x3, y3, z3);
    }

    private PointG2 doubleP() {
      Fp2 w = this.x.square().mul(3);
      Fp2 s = this.y.mul(this.z);
      Fp2 ss = s.square();
      Fp2 sss = ss.mul(s);
      Fp2 b = this.x.mul(this.y).mul(s);
      Fp2 h = w.square().sub(b.mul(8));
      Fp2 x3 = h.mul(s).mul(2);
      Fp2 y3 = w.mul(b.mul(4).sub(h)).sub(
        this.y.square().mul(8).mul(ss)
      );
      Fp2 z3 = sss.mul(8);
      return new PointG2(x3, y3, z3);
    }

    private boolean isZero() {
      return this.z.isZero();
    }

    PointG2 clearCofactor() {
      PointG2 t1 = this.mulCurveX();
      PointG2 t2 = this.psi();
      PointG2 t3 = this.doubleP();
      t3 = t3.psi2();
      t3 = t3.sub(t2);
      t2 = t1.add(t2);
      t2 = t2.mulCurveX();
      t3 = t3.add(t2);
      t3 = t3.sub(t1);
      PointG2 q = t3.sub(this);
      return q;
    }

    private PointG2 sub(PointG2 p) {
      return this.add(p.neg());
    }

    private PointG2 neg() {
      return new PointG2(x, y.neg(), z);
    }

    private PointG2 psi2() {
      PointG2 p = toAffine();
      return new PointG2(p.x.mul(PSI2_C1), p.y.neg(), p.z);
    }

    private PointG2 psi() {
      PointG2 p = toAffine();
      Fp2 x2 = WSQ_INV.mulByFp2(p.x).frobeniusMap(1).mul(WSQ).c0.c0;
      Fp2 y2 = WCU_INV.mulByFp2(p.y).frobeniusMap(1).mul(WCU).c0.c0;
      return new PointG2(x2, y2, p.z);
    }

    private PointG2 mulCurveX() {
      return this.mulUnsafe(CURVE_X).neg();
    }

    private PointG2 mulUnsafe(BigInteger n) {
      PointG2 point = PointG2.ZERO;
      PointG2 d = this;

      int bitLength = n.bitLength();
      for (int i = 0; i < bitLength; i++) {
        if (n.testBit(i)) {
          point = point.add(d);
        }

        d = d.doubleP();
      }

      return point;
    }

    PointG2 toAffine() {
      Fp2 invZ = this.z.inv();
      return new PointG2(this.x.mul(invZ), this.y.mul(invZ), Fp2.ONE);
    }

    byte[] toByteArray(boolean compressed) {
      PointG2 p = this.toAffine();
      byte[] result = new byte[Fp2.SIZE * (compressed ? 1 : 2)];
      p.x.serialize(result, 0);

      if (compressed) {
        result[0] |= (byte) 0x80;
        BigInteger tmp = p.y.im.isZero() ? p.y.re.i.shiftLeft(1) : p.y.im.i.shiftLeft(1);
        if (tmp.compareTo(P) > 0) {
          result[0] |= 0x20;
        }
      } else {
        p.y.serialize(result, Fp2.SIZE);
      }

      return result;
    }

    @Override
    public boolean equals(Object o) {
      if (o == this) {
        return true;
      }

      if (!(o instanceof PointG2)) {
        return false;
      }

      PointG2 p = (PointG2) o;
      return p.x.equals(this.x) && p.y.equals(this.y) && p.z.equals(this.z); 
    }
  }
}
