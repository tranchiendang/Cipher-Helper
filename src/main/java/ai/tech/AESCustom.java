package ai.tech;

import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AESCustom {

    private static final Charset UTF8_CHARSET = Charset.forName("UTF-8");
	private static final String CIPHER_MODE = "AES/CBC/PKCS5PADDING";
	private static final String CIPHER_ROOT = "AES";

	private AESCustom() {

	}

	/**
	 * This method is used to generate Secret Key.
	 *
	 * @return SecretKey Key for encrypt/ decrypt
	 * @throws NoSuchAlgorithmException when exceptional condition happens
	 */
	public static SecretKey generateSecretKey() throws NoSuchAlgorithmException {
		return KeyGenerator.getInstance(CIPHER_ROOT).generateKey();
	}

	/**
	 * This method is used to get Secret Key from string.
	 *
	 * @param key Base64 encoded form of String, represent for secret key
	 * @return SecretKey A secret key
	 */
	public static SecretKey convertStringToKey(String key) {
		SecretKeySpec resKey = new SecretKeySpec(Base64.getDecoder().decode(key), CIPHER_ROOT);
		return resKey;
	}

	/**
	 * This method is used to encrypt message.
	 *
	 * @param message   Message need to be encrypted
	 * @param secretKey Secret key used for encryption process
	 * @return String Encrypted message after processed
	 * @throws InvalidKeyException when this exceptional condition happens
	 * @throws NoSuchAlgorithmException when this exceptional condition happens
	 * @throws NoSuchPaddingException when this exceptional condition happens
	 * @throws IllegalBlockSizeException when this exceptional condition happens
	 * @throws BadPaddingException when this exceptional condition happens
	 * @throws InvalidAlgorithmParameterException when this exceptional condition happens
	 */
	public static String encrypt(String message, SecretKey secretKey) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		byte[] utf8 = message.getBytes(UTF8_CHARSET);
		byte[] encryptString = getCipher(Cipher.ENCRYPT_MODE, secretKey).doFinal(utf8);

		return Base64.getEncoder().encodeToString(encryptString);
	}

	/**
	 * This method is used to decrypt message.
	 *
	 * @param message   Message need to be decrypted
	 * @param secretKey Secret key used for decryption process
	 * @return String Decrypted message after processed
	 * @throws InvalidKeyException when this exceptional condition happens
	 * @throws NoSuchAlgorithmException when this exceptional condition happens
	 * @throws NoSuchPaddingException when this exceptional condition happens
	 * @throws IllegalBlockSizeException when this exceptional condition happens
	 * @throws BadPaddingException when this exceptional condition happens
	 * @throws InvalidAlgorithmParameterException when this exceptional condition happens
	 */
	public static String decrypt(String message, SecretKey secretKey) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		byte[] utf8 = Base64.getDecoder().decode(message);
		byte[] decryptString = getCipher(Cipher.DECRYPT_MODE, secretKey).doFinal(utf8);

		return new String(decryptString, UTF8_CHARSET);
	}

	private static Cipher getCipher(int mode, SecretKey secretKey) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {
		Cipher cipher = Cipher.getInstance(CIPHER_MODE);
		AlgorithmParameterSpec param = new IvParameterSpec(secretKey.getEncoded());

		cipher.init(mode, secretKey, param);
		return cipher;
	}
}