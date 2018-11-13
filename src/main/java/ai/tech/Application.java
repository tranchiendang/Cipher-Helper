package ai.tech;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

import javax.crypto.SecretKey;

public class Application {
    public static void main(String[] args) throws Exception {
        
        String message = "your message is here";
        
        // RSA
        // generate public and private keys
        KeyPair keyPair = RSACustom.buildKeyPair();
        PublicKey pubKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();
        
        // encrypt the message
        String encryptedMessage = RSACustom.encrypt(pubKey, message);     
        System.out.println(encryptedMessage);
        
        // decrypt the message
        String decryptedMessage = RSACustom.decrypt(privateKey, encryptedMessage);                                 
        System.out.println(decryptedMessage);
        System.out.println("------------");
        
        // AES
        SecretKey key = AESCustom.generateSecretKey();
        System.out.println(Base64.getEncoder().encodeToString(key.getEncoded()));
    }
}



