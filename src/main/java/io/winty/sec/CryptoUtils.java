package io.winty.sec;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

public class CryptoUtils {
    private static final String AES_GCM = "AES/GCM/NoPadding";
    private static final int GCM_NONCE_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 16 * 8;
    private static final SecureRandom random = new SecureRandom();

    public static byte[] encrypt(byte[] plainText, SecretKey key) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(AES_GCM);
        byte[] nonce = generateNonce();
        GCMParameterSpec spec = getGCMParametersSpec(nonce);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        byte[] encryptedData = cipher.doFinal(plainText);
        return concat(nonce, encryptedData);
    }

    public static byte[] decrypt(byte[] cipherText, SecretKey key) throws GeneralSecurityException {
        Cipher cipher = Cipher.getInstance(AES_GCM);
        byte[] nonce = getNonceFromBytes(cipherText);
        byte[] encryptedData = getPayloadFromBytes(cipherText);
        GCMParameterSpec spec = getGCMParametersSpec(nonce);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);
        return cipher.doFinal(encryptedData);
    }
    
    private static GCMParameterSpec getGCMParametersSpec( byte[] nonce ){
        return new GCMParameterSpec(GCM_TAG_LENGTH, nonce);
    }

    private static byte[] getNonceFromBytes(byte[] cipherData){
        byte[] nonce = new byte[GCM_NONCE_LENGTH];
        System.arraycopy(cipherData, 0, nonce, 0, GCM_NONCE_LENGTH);
        return nonce;
    }
    
    private static byte[] getPayloadFromBytes(byte[] cipherData){
        byte[] payload = new byte[cipherData.length - GCM_NONCE_LENGTH];
        System.arraycopy(cipherData, GCM_NONCE_LENGTH, payload, 0, payload.length);
        return payload;
    }
    
    private static byte[] generateNonce(){
        byte[] nonce = new byte[GCM_NONCE_LENGTH];
        random.nextBytes(nonce);
        return nonce;
    }

    private static byte[] concat(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }
    
}