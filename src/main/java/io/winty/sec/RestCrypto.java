package io.winty.sec;

import java.security.GeneralSecurityException;
import java.util.Base64;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class RestCrypto {
    
    private static final String SPLIT_CHAR = ":"; 

    private final KeyManager keyManager;
    private final SecretKey kek;
    
    
    public RestCrypto(String base64EncodedKek) throws GeneralSecurityException {
        byte[] decodedKey = Base64.getDecoder().decode(base64EncodedKek);
        this.kek = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
        this.keyManager = new KeyManager();
    }

    public String storeSecureData(String data) throws Exception{
        SecretKey dek = keyManager.generateDEK();
        byte[] encryptedData = CryptoUtils.encrypt(data.getBytes(), dek);
        byte[] wrappedDek = CryptoUtils.encrypt(dek.getEncoded(), kek);
        return Base64.getEncoder().encodeToString(wrappedDek) + SPLIT_CHAR + Base64.getEncoder().encodeToString(encryptedData);
    }
    public String retrieveSecureData(String cipheredData) throws Exception {
        String[] parts = cipheredData.split(SPLIT_CHAR);
        byte[] wrappedDek = Base64.getDecoder().decode(parts[0]);
        byte[] cipheredPayload = Base64.getDecoder().decode(parts[1]);
        
        byte[] dekBytes = CryptoUtils.decrypt(wrappedDek, kek);
        SecretKey dek = new SecretKeySpec(dekBytes, 0, dekBytes.length, "AES");
        byte[] decryptedData = CryptoUtils.decrypt(cipheredPayload, dek);
        return new String(decryptedData);
    }
    
}