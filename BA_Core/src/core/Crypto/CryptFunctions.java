package core.Crypto;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.macs.ISO9797Alg3Mac;
import org.bouncycastle.crypto.paddings.ISO7816d4Padding;
import org.bouncycastle.crypto.params.KeyParameter;

import core.Exceptions.CryptoException;
import core.Logging.LogState;

/**
 * This class contains a set of cryptographic functions regardless of the actual purpose.
 * 
 * @author Mark Forjahn
 *
 */
public class CryptFunctions {
	
	/**
	 * Function that can create a message digest of data 
	 * @param data input data
	 * @param algorithm algortihm to use ("SHA", "MD5")
	 * @param state actual state
	 * @return message digest 
	 * @throws CryptoException 
	 */
	public static byte[] createMessageDigest(byte[] data, String algorithm, LogState state) throws CryptoException{
		byte[] result = null;
		try {
			MessageDigest md = MessageDigest.getInstance(algorithm);
			md.update(data, 0, data.length);			
			result = md.digest();
		} catch (Exception e) {
			throw new CryptoException(e.getMessage(), state);
		}
		return result;
	}	

	/**
	 * 3DES function (encryption + decryption)
	 * @param key key for encryption/ decryption
	 * @param data data that needs to be encrypted/ decrypted
	 * @param iv iv to use
	 * @param encrypt true: encrypt/ false: decrypt
	 * @param state actual state
	 * @return
	 * @throws CryptoException
	 */
	public static byte[] TripleDES(byte[] key, byte[]data, byte[] iv, boolean encrypt, LogState state) throws CryptoException{
		byte[] output = null;
		try{
			DESedeKeySpec keySpec = new DESedeKeySpec(key);
			IvParameterSpec ivSpec = new IvParameterSpec(iv);
			SecretKey skey = SecretKeyFactory.getInstance("DESede").generateSecret(keySpec);
			Cipher encrypter = Cipher.getInstance("DESede/CBC/NoPadding");
			encrypter.init(encrypt == true ? Cipher.ENCRYPT_MODE:Cipher.DECRYPT_MODE, skey, ivSpec);
			output = encrypter.doFinal(data);
		}
		catch(BadPaddingException e){
			throw new CryptoException(e.getMessage(), state);
		} catch (InvalidKeyException e) {
			throw new CryptoException(e.getMessage(), state);
		} catch (InvalidKeySpecException e) {
			throw new CryptoException(e.getMessage(), state);
		} catch (NoSuchAlgorithmException e) {
			throw new CryptoException(e.getMessage(), state);
		} catch (NoSuchPaddingException e) {
			throw new CryptoException(e.getMessage(), state);
		} catch (InvalidAlgorithmParameterException e) {
			throw new CryptoException(e.getMessage(), state);
		} catch (IllegalBlockSizeException e) {
			throw new CryptoException(e.getMessage(), state);
		}
		return output;
	}
	

	/**
	 * AES function (encryption + decryption)
	 * @param key key for encryption/ decryption
	 * @param data data that needs to be encrypted/ decrypted
	 * @param iv iv to use
	 * @param encrypt true: encrypt/ false: decrypt
	 * @param state actual state
	 * @return
	 * @throws CryptoException
	 */
	public static byte[] AES(byte[] key, byte[]data, byte[] iv, boolean encrypt, LogState state) throws CryptoException{
		
		byte[] output = null;
		try {
			SecretKeySpec  skey = new SecretKeySpec(key, "AES");
			AlgorithmParameterSpec paramSpec = new IvParameterSpec(iv);
			Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
			cipher.init(encrypt == true ? Cipher.ENCRYPT_MODE:Cipher.DECRYPT_MODE, skey, paramSpec);
			output = cipher.doFinal(data);
		} catch (BadPaddingException e){
			
		} catch (InvalidKeyException e) {
			throw new CryptoException(e.getMessage(), state);
		} catch (InvalidAlgorithmParameterException e) {
			throw new CryptoException(e.getMessage(), state);
		} catch (IllegalBlockSizeException e) {
			throw new CryptoException(e.getMessage(), state);
		} catch (NoSuchAlgorithmException e) {
			throw new CryptoException(e.getMessage(), state);
		} catch (NoSuchPaddingException e) {
			throw new CryptoException(e.getMessage(), state);
		}
		
		return output;

	}
	
	/**
	 * Function to create a new can
	 * @return new generated can
	 * @throws NoSuchAlgorithmException
	 */
	public static int createNewCAN() throws NoSuchAlgorithmException{		
		int can = RandomCreator.createSecureRandomInt(999999);
		return can;
	}
	
	/**
	 * This method creates a CMAC of data by using a specific key.
	 * @param key K_MAC, which was derived from the key agreement
	 * @param data data
	 * @return authenticated data
	 */
	public static byte[] AES_MAC(byte[] key, byte[]data){
		// AES SHALL be used in CMAC-mode with a MAC length of 8 bytes.
		BlockCipher cipher = new AESFastEngine();
		Mac mac = new CMac(cipher, 64); 
	
		KeyParameter keyParam = new KeyParameter(key);
		mac.init(keyParam);	
		mac.update(data, 0, data.length);
	
		byte[] output = new byte[8];	
		mac.doFinal(output, 0);

		return output;
	}	
	
	/**
	 * This method creates a CMAC of data by using a specific key.
	 * @param key K_MAC, which was derived from the key agreement
	 * @param data data
	 * @return authenticated data
	 */
	public static byte[] TripleDES_MAC(byte[] key, byte[]data){
	
		//3DES SHALL be used in Retail-mode according to ISO/IEC 9797-1 [16] MAC algorithm 3 / padding method 2 with block cipher DES and IV=0.			
		BlockCipher cipher = new DESEngine();
		Mac mac = new ISO9797Alg3Mac(cipher, 64, new ISO7816d4Padding());
		KeyParameter keyP = new KeyParameter(key);
		mac.init(keyP);
		mac.update(data, 0, data.length);
		byte[] output = new byte[8];
		mac.doFinal(output, 0);
		return output;
	}
	
}
