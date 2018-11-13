package ai.tech;

import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

public class RSACustom {

    private static final Charset UTF8_CHARSET = Charset.forName("UTF-8");
	private static final String CIPHER_ROOT = "RSA";

	private RSACustom() {

	}

	/**
	 * This method is used to generate public & private key.
	 *
	 * @return KeyPairGenerator This returns key pair, using such methods getPublic() & getPrivate to get concrete key
	 * @throws NoSuchAlgorithmException when this exceptional condition happens
	 */
	public static KeyPair buildKeyPair() throws NoSuchAlgorithmException {
		final int keySize = 2048;
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(CIPHER_ROOT);
		keyPairGenerator.initialize(keySize);
		return keyPairGenerator.genKeyPair();
	}

	/**
	 * This method is used to get private key from arbitrary string.
	 *
	 * @param privateKeyString Base64 encoded form of String, represent for private key
	 * @return PrivateKey A Private Key from input String
	 * @throws InvalidKeySpecException when this exceptional condition happens
	 * @throws NoSuchAlgorithmException when this exceptional condition happens
	 */
	public static PrivateKey getPrivateKeyFromString(String privateKeyString) throws InvalidKeySpecException, NoSuchAlgorithmException {
		byte[] privateKeyInByte = Base64.getDecoder().decode(privateKeyString);
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateKeyInByte);

		return getKeyFactory().generatePrivate(keySpec);
	}

	/**
	 * This medtho is used to get public key from arbitrary string.
	 *
	 * @param publicKeyString Base64 encoded from of String, represent for public key
	 * @return PublicKey A Public key from input String
	 * @throws InvalidKeySpecException when this exceptional condition happens
	 * @throws NoSuchAlgorithmException when this exceptional condition happens
	 */
	public static PublicKey getPublicKeyFromString(String publicKeyString)
			throws InvalidKeySpecException, NoSuchAlgorithmException {
		byte[] publicKeyInByte = Base64.getDecoder().decode(publicKeyString);
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKeyInByte);

		return getKeyFactory().generatePublic(keySpec);
	}

	/**
	 * This method is used to encrypt message.
	 *
	 * @param publicKey Public key used for encryption process
	 * @param message   Message need to be encrypted
	 * @return String Encrypted message after processed
	 * @throws Exception when this exceptional condition happens
	 */
	public static String encrypt(PublicKey publicKey, String message) throws Exception {
		return Base64.getEncoder().encodeToString(getCipher(Cipher.ENCRYPT_MODE, publicKey).doFinal(message.getBytes(UTF8_CHARSET)));
	}

	/**
	 * This method is used to decrypt message.
	 *
	 * @param privateKey Private key used for decrypted process
	 * @param message    Message need to be decrypted
	 * @return String Decrypted message after processed
	 * @throws Exception when this exceptional condition happens
	 */
	public static String decrypt(PrivateKey privateKey, String message) throws Exception {
		byte[] decodeString = Base64.getDecoder().decode(message);

		return new String(getCipher(Cipher.DECRYPT_MODE, privateKey).doFinal(decodeString), UTF8_CHARSET);
	}

	/**
	 * This method is helper method, provide key factory for getting public private key from string.
	 *
	 * @return KeyFactory Helper method for 2 top methods
	 * @throws NoSuchAlgorithmException when this exceptional condition happens
	 */
	private static KeyFactory getKeyFactory() throws NoSuchAlgorithmException {
		return KeyFactory.getInstance(CIPHER_ROOT);
	}

	private static Cipher getCipher(int mode, Key key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException {
		Cipher cipher = Cipher.getInstance(CIPHER_ROOT);
		cipher.init(mode, key);

		return cipher;
	}
}