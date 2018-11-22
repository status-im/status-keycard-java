package im.status.hardwallet_lite_android.globalplatform;

import android.util.Base64;

import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import static android.util.Base64.NO_PADDING;

public class Crypto {
    public static final byte[] NullBytes8 = new byte[]{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    public static long PIN_BOUND = 999999L;
    public static long PUK_BOUND = 999999999999L;

    public static byte[] deriveSCP02SessionKey(byte[] cardKey, byte[] seq, byte[] purposeData) {
        byte[] key24 = resizeKey24(cardKey);

        try {
            byte[] derivationData = new byte[16];
            // 2 bytes constant
            System.arraycopy(purposeData, 0, derivationData, 0, 2);
            // 2 bytes sequence counter + 12 bytes 0x00
            System.arraycopy(seq, 0, derivationData, 2, 2);

            SecretKeySpec tmpKey = new SecretKeySpec(key24, "DESede");

            Cipher cipher = Cipher.getInstance("DESede/CBC/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, tmpKey, new IvParameterSpec(NullBytes8));

            return cipher.doFinal(derivationData);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new IllegalStateException("error generating session keys.", e);
        } catch (InvalidKeyException | IllegalBlockSizeException | BadPaddingException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException("error generating session keys.", e);
        }
    }

    public static byte[] appendDESPadding(byte[] data) {
        int paddingLength = 8 - (data.length % 8);
        byte[] newData = new byte[data.length + paddingLength];
        System.arraycopy(data, 0, newData, 0, data.length);
        newData[data.length] = (byte)0x80;

        return newData;
    }

    public static boolean verifyCryptogram(byte[] key, byte[] hostChallenge, byte[] cardChallenge, byte[] cardCryptogram) {
        byte[] data = new byte[hostChallenge.length + cardChallenge.length];
        System.arraycopy(hostChallenge, 0, data, 0, hostChallenge.length);
        System.arraycopy(cardChallenge, 0, data, hostChallenge.length, cardChallenge.length);
        byte[] paddedData = appendDESPadding(data);
        byte[] calculated = mac3des(key, paddedData, NullBytes8);

        return Arrays.equals(calculated , cardCryptogram);
    }

    public static byte[] mac3des(byte[] keyData, byte[] data, byte[] iv) {
        try {
            SecretKeySpec key = new SecretKeySpec(resizeKey24(keyData), "DESede");
            Cipher cipher = Cipher.getInstance("DESede/CBC/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
            byte[] result = cipher.doFinal(data, 0, 24);
            byte[] tail = new byte[8];
            System.arraycopy(result, 16, tail, 0, 8);
            return tail;
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("error calculating mac.", e);
        }
    }

    public static byte[] macFull3des(byte[] keyData, byte[] data, byte[] iv) {
        try {
            SecretKeySpec keyDes = new SecretKeySpec(resizeKey8(keyData), "DES");
            Cipher cipherDes = Cipher.getInstance("DES/CBC/NoPadding");
            cipherDes.init(Cipher.ENCRYPT_MODE, keyDes, new IvParameterSpec(iv));

            SecretKeySpec keyDes3 = new SecretKeySpec(resizeKey24(keyData), "DESede");
            Cipher cipherDes3 = Cipher.getInstance("DESede/CBC/NoPadding");
            byte[] des3Iv = iv.clone();

            if (data.length > 8) {
                byte[] tmp = cipherDes.doFinal(data, 0, data.length - 8);
                System.arraycopy(tmp, tmp.length - 8, des3Iv, 0, 8);
            }

            cipherDes3.init(Cipher.ENCRYPT_MODE, keyDes3, new IvParameterSpec(des3Iv));
            byte[] result = cipherDes3.doFinal(data, data.length - 8, 8);
            byte[] tail = new byte[8];
            System.arraycopy(result, result.length - 8, tail, 0, 8);
            return tail;
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("error generating full triple DES MAC.", e);
        }
    }

    public static byte[] resizeKey24(byte[] keyData) {
        byte[] key = new byte[24];
        System.arraycopy(keyData, 0, key, 0, 16);
        System.arraycopy(keyData, 0, key, 16, 8);

        return key;
    }

    public static byte[] resizeKey8(byte[] keyData) {
        byte[] key = new byte[8];
        System.arraycopy(keyData, 0, key, 0, 8);

        return key;
    }

    public static byte[] encryptICV(byte[] macKeyData, byte[] mac) {
        try {
            Cipher cipher = Cipher.getInstance("DES/ECB/NoPadding");
            SecretKeySpec key = new SecretKeySpec(resizeKey8(macKeyData), "DES");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(mac);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException("error generating ICV.", e);
        }
    }

    public static byte[] randomBytes(int length) {
        SecureRandom random = new SecureRandom();
        byte data[] = new byte[length];
        random.nextBytes(data);

        return data;
    }

    public static long randomLong(long bound) {
        SecureRandom random = new SecureRandom();
        return Math.abs(random.nextLong()) % bound;
    }

    public static String randomToken(int length) {
        return Base64.encodeToString(randomBytes(length),NO_PADDING);
    }
}
