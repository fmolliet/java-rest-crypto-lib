package io.winty.sec;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class RestCrypto {
    
    private static final String ALGORITHM = "AES";
    private static final String AES_GCM = "AES/GCM/NoPadding";
    private static final int DEK_KEY_SIZE = 256;
    private static final String SPLIT_CHAR = ":"; 
    private static final int GCM_NONCE_LENGTH = 12; 
    private static final int GCM_TAG_LENGTH = 16 * 8;
    
    private static SecureRandom random;
    
    private final SecretKey kek;
    
    
    public RestCrypto(String base64EncodedKek) throws GeneralSecurityException {
        byte[] decodedKey = Base64.getDecoder().decode(base64EncodedKek);
        this.kek = new SecretKeySpec(decodedKey, 0, decodedKey.length, ALGORITHM);
        random = new SecureRandom();
    }
    
    private SecretKey generateDEK() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
        keyGenerator.init(DEK_KEY_SIZE);
        return keyGenerator.generateKey();
    }

    public String storeSecureData(String data) throws Exception{
        SecretKey dek = generateDEK();
        return wrap(dek)+ SPLIT_CHAR + encrypt(data.getBytes(), dek);
    }
    public String retrieveSecureData(String cipheredData) throws Exception {
        String[] parts = cipheredData.split(SPLIT_CHAR);
        byte[] wrappedDek = Base64.getDecoder().decode(parts[0]);
        byte[] cipheredPayload = Base64.getDecoder().decode(parts[1]);
        
        SecretKey dek = unwrap(wrappedDek);
        return decrypt(cipheredPayload, dek);
    }
    
    private String encrypt(byte[] plainTextBytes, SecretKey dek) throws Exception {
        byte[] nonce = generateNonce();
        Cipher cipher = Cipher.getInstance(AES_GCM);
        cipher.init(Cipher.ENCRYPT_MODE, dek, getGCMParametersSpec(nonce));

        byte[] encryptedData = cipher.doFinal(plainTextBytes);
        return Base64.getEncoder().encodeToString(concat(nonce,encryptedData));
    }
    
    private String decrypt(byte[] encryptedDataWithNonce, SecretKey dek) throws Exception {
        byte[] nonce = getNonceFromBytes(encryptedDataWithNonce);
        byte[] encryptedData = getPayloadFromBytes(encryptedDataWithNonce);
        Cipher cipher = Cipher.getInstance(AES_GCM);
        cipher.init(Cipher.DECRYPT_MODE, dek, getGCMParametersSpec(nonce));

        byte[] decryptedData = cipher.doFinal(encryptedData);
        return new String(decryptedData);
    }
    
    private String wrap(SecretKey keyToWrap) throws Exception {
        byte[] nonce = generateNonce();
        Cipher cipher = Cipher.getInstance(AES_GCM);
        cipher.init(Cipher.WRAP_MODE, kek, getGCMParametersSpec(nonce));

        byte[] wrappedKey = cipher.wrap(keyToWrap);
        return Base64.getEncoder().encodeToString(concat(nonce, wrappedKey));
    }
    
    private SecretKey unwrap(byte[] wrappedKeyDataWithNonce) throws Exception {
        byte[] nonce = getNonceFromBytes(wrappedKeyDataWithNonce);

        byte[] wrappedKey = getPayloadFromBytes(wrappedKeyDataWithNonce);
        Cipher cipher = Cipher.getInstance(AES_GCM);
        cipher.init(Cipher.UNWRAP_MODE, kek, getGCMParametersSpec(nonce));

        return (SecretKey) cipher.unwrap(wrappedKey, "AES", Cipher.SECRET_KEY);
    }
    
    private GCMParameterSpec getGCMParametersSpec( byte[] nonce ){
        return new GCMParameterSpec(GCM_TAG_LENGTH, nonce);
    }
    
    private byte[] getNonceFromBytes(byte[] cipherData){
        byte[] nonce = new byte[GCM_NONCE_LENGTH];
        System.arraycopy(cipherData, 0, nonce, 0, GCM_NONCE_LENGTH);
        return nonce;
    }
    
    private byte[] getPayloadFromBytes(byte[] cipherData){
        byte[] payload = new byte[cipherData.length - GCM_NONCE_LENGTH];
        System.arraycopy(cipherData, GCM_NONCE_LENGTH, payload, 0, payload.length);
        return payload;
    }
    
    private byte[] generateNonce(){
        byte[] nonce = new byte[GCM_NONCE_LENGTH];
        random.nextBytes(nonce);
        return nonce;
    }

    private byte[] concat(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }
}