package io.winty.sec;

import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class RestCrypto {
    
    private static final String ALGORITHM = "AES";
    private static final int DEK_KEY_SIZE = 256;
    private static final String SPLIT_CHAR = ":"; 
    
    private final SecretKey kek;
    
    
    public RestCrypto(String base64EncodedKek) {
        byte[] decodedKey = Base64.getDecoder().decode(base64EncodedKek);
        this.kek = new SecretKeySpec(decodedKey, 0, decodedKey.length, ALGORITHM);
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
}