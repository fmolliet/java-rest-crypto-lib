package io.winty.sec;

import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class RestCrypto {
    
    private static final String ALGORITHM = "AES";
    private static final int DEK_KEY_SIZE = 256;
    private static final String SPLIT_CHAR = ":"; 
    private static final int GCM_NONCE_LENGTH = 12; 
    private static final int GCM_TAG_LENGTH = 16 * 8;
    
    private static SecureRandom random;
    
    private final SecretKey kek;
    
    
    public RestCrypto(String base64EncodedKek) {
        byte[] decodedKey = Base64.getDecoder().decode(base64EncodedKek);
        this.kek = new SecretKeySpec(decodedKey, 0, decodedKey.length, ALGORITHM);
        random = new SecureRandom();
    }
    
    private SecretKey generateDEK() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
        keyGenerator.init(DEK_KEY_SIZE);
        return keyGenerator.generateKey();
    }

    public String encrypt(String data) throws Exception {
        SecretKey dek = generateDEK();
        Cipher dataCipher = Cipher.getInstance(ALGORITHM);
        dataCipher.init(Cipher.ENCRYPT_MODE, dek);

        byte[] encryptedData = dataCipher.doFinal(data.getBytes());

        Cipher kekCipher = Cipher.getInstance(ALGORITHM);
        kekCipher.init(Cipher.WRAP_MODE, kek);
        byte[] encryptedDek = kekCipher.wrap(dek);

        return Base64.getEncoder().encodeToString(encryptedDek) + SPLIT_CHAR + Base64.getEncoder().encodeToString(encryptedData);
    }

   
    public String decrypt(String encryptedDataWithDek) throws Exception {
        String[] parts = encryptedDataWithDek.split(SPLIT_CHAR);
        byte[] encryptedDek = Base64.getDecoder().decode(parts[0]);
        byte[] encryptedData = Base64.getDecoder().decode(parts[1]);

        Cipher kekCipher = Cipher.getInstance(ALGORITHM);
        kekCipher.init(Cipher.UNWRAP_MODE, kek);
        SecretKey dek = (SecretKey) kekCipher.unwrap(encryptedDek, ALGORITHM, Cipher.SECRET_KEY);

        Cipher dataCipher = Cipher.getInstance(ALGORITHM);
        dataCipher.init(Cipher.DECRYPT_MODE, dek);

        byte[] decryptedData = dataCipher.doFinal(encryptedData);
        return new String(decryptedData);
    }
    
    public String storeSecureData(String data) throws Exception{
        SecretKey dek = generateDEK();
        return wrap(dek)+ SPLIT_CHAR + encryptGCM(data, dek);
    }
    public String retrieveSecureData(String cipheredData) throws Exception {
        String[] parts = cipheredData.split(SPLIT_CHAR);
        byte[] wrappedDek = Base64.getDecoder().decode(parts[0]);
        
        SecretKey dek = unwrap(wrappedDek);
        return decryptGCM(parts[1]+SPLIT_CHAR+parts[2], dek);
    }
    
    private String encryptGCM(String plaintext, SecretKey dek) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

        byte[] nonce = new byte[GCM_NONCE_LENGTH];
        random.nextBytes(nonce); // Nonce seguro e aleatório

        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, dek, spec);

        byte[] encryptedData = cipher.doFinal(plaintext.getBytes());
        return Base64.getEncoder().encodeToString(nonce) + SPLIT_CHAR + Base64.getEncoder().encodeToString(encryptedData);
    }
    
    private String decryptGCM(String encryptedDataWithNonce, SecretKey dek) throws Exception {
        String[] parts = encryptedDataWithNonce.split(SPLIT_CHAR);
        byte[] nonce = Base64.getDecoder().decode(parts[0]);
        byte[] encryptedData = Base64.getDecoder().decode(parts[1]);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, nonce);
        cipher.init(Cipher.DECRYPT_MODE, dek, spec);

        byte[] decryptedData = cipher.doFinal(encryptedData);
        return new String(decryptedData);
    }
    
    private String wrap(SecretKey keyToWrap) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] nonce = new byte[GCM_NONCE_LENGTH];
        (new SecureRandom()).nextBytes(nonce);

        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, nonce);
        cipher.init(Cipher.WRAP_MODE, kek, spec);

        byte[] wrappedKey = cipher.wrap(keyToWrap);
        return Base64.getEncoder().encodeToString(concat(nonce, wrappedKey));
    }
    
    private SecretKey unwrap(byte[] wrappedKeyData) throws Exception {
        byte[] nonce = new byte[GCM_NONCE_LENGTH];
        System.arraycopy(wrappedKeyData, 0, nonce, 0, GCM_NONCE_LENGTH);

        byte[] wrappedKey = new byte[wrappedKeyData.length - GCM_NONCE_LENGTH];
        System.arraycopy(wrappedKeyData, GCM_NONCE_LENGTH, wrappedKey, 0, wrappedKey.length);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, nonce);
        cipher.init(Cipher.UNWRAP_MODE, kek, spec);

        return (SecretKey) cipher.unwrap(wrappedKey, "AES", Cipher.SECRET_KEY);
    }

    private byte[] concat(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }
}