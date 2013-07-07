package core.Authentication.PACE;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;

import core.Crypto.CryptFunctions;
import core.Exceptions.CryptoException;
import core.Exceptions.PACEFunctionsException;
import core.Logging.Log;
import core.Logging.LogLevel;
import core.Logging.LogState;
import core.Logging.LogType;
import core.Support.HelperClass;

/**
 * This class provides all necessary functions for PACE.
 * 
 * @author Mark Forjahn
 * 
 */
public class PACEFunctions {

	/**
	 * This method creates a hash
	 * 
	 * @param input
	 *            data that needs to be hashed
	 * @param algorithm
	 *            hash algorithm -> "SHA1" or "SHA-256" for PACE
	 * @return hash of input
	 * @throws PACEFunctionsException
	 */
	public static byte[] h(byte[] input, String algorithm)
			throws PACEFunctionsException {

		Log.addEntry("Function H(): Create hash of \""
				+ HelperClass.toHexString(input)
				+ "\" by using " + algorithm,
				LogType.INFORMATION, LogState.AUTHENTICATE,
				LogLevel.LOW);
		byte[] ret = null;
		if (algorithm.equals("SHA1")
				|| algorithm.equals("SHA-256")) {
			try {
				ret = CryptFunctions.createMessageDigest(
						input, algorithm,
						LogState.AUTHENTICATE);
			} catch (CryptoException e) {
				throw new PACEFunctionsException(
						"Could not create hash",
						LogState.AUTHENTICATE);
			}
		} else {
			throw new PACEFunctionsException(
					"Could not create hash: Algorithm could not be identified!",
					LogState.AUTHENTICATE);
		}
		Log.addEntry("Function H(): Hash created: "
				+ HelperClass.toHexString(ret),
				LogType.INFORMATION, LogState.AUTHENTICATE,
				LogLevel.LOW);

		return ret;
	}

	/**
	 * This is the PACE key derivation function. Three keys can be derived: Kpi,
	 * K_MAC and K_ENC
	 * 
	 * @param k
	 *            key to derive
	 * @param c
	 *            1: K_ENC; 2: K_MAC; 3:Kpi
	 * @param algorithm
	 *            current used algorithm
	 * @return the derived key
	 * @throws PACEFunctionsException
	 */
	public static byte[] kdf(byte[] k, int c,
			Algorithms algorithm)
			throws PACEFunctionsException {

		Log.addEntry("Function KDF(k, c): k = "
				+ HelperClass.toHexString(k) + " | c = "
				+ c, LogType.INFORMATION,
				LogState.AUTHENTICATE, LogLevel.LOW);

		if (!(c == 1 || c == 2 || c == 3)) {
			throw new PACEFunctionsException(
					"Parameter \"c\" must contain the value 1,2 or 3!",
					LogState.AUTHENTICATE);
		}

		byte[] cBytes = HelperClass.intToByteArray(c); // converts int to byte
		byte data[] = HelperClass.concatenateByteArrays(k,
				cBytes); // concatenates
							// k and c

		Log.addEntry(
				"Function KDF(k, c): concatenated bytes: "
						+ HelperClass.toHexString(data),
				LogType.INFORMATION, LogState.AUTHENTICATE,
				LogLevel.LOW);

		byte[] keydata = null;

		if (algorithm.equals(Algorithms._3DES_112)) {
			keydata = h(data, "SHA1");
			Log.addEntry(
					"Function KDF(k, c): Will now create keys for 3DES usage. The third key will be equivalent to the first key!",
					LogType.INFORMATION,
					LogState.AUTHENTICATE, LogLevel.LOW);
			byte[] octets = new byte[24];
			for (int i = 0; i < 16; i++) {
				octets[i] = keydata[i];
			}
			for (int i = 16; i < 24; i++) {
				octets[i] = octets[i - 16]; // third key equivalent to first key
			}
			keydata = octets;
			Log.addEntry(
					"Function KDF(k, c): 3DES key(s) (each key has a length of 8 Bytes) created: "
							+ HelperClass
									.toHexString(keydata),
					LogType.INFORMATION,
					LogState.AUTHENTICATE, LogLevel.LOW);

		} else if (algorithm.equals(Algorithms._AES_128)) {
			keydata = h(data, "SHA1");
			Log.addEntry(
					"Function KDF(k, c): Will now create keys for AES-128 usage!",
					LogType.INFORMATION,
					LogState.AUTHENTICATE, LogLevel.LOW);

			byte[] octets = new byte[16];
			for (int i = 0; i < octets.length; i++) {
				octets[i] = keydata[i];
			}
			keydata = octets;
			Log.addEntry(
					"Function KDF(k, c): AES-128 key created: "
							+ HelperClass
									.toHexString(keydata),
					LogType.INFORMATION,
					LogState.AUTHENTICATE, LogLevel.LOW);

		} else if (algorithm.equals(Algorithms._AES_192)) {
			keydata = h(data, "SHA-256");
			Log.addEntry(
					"Function KDF(k, c): Will now create keys for AES-192 usage!",
					LogType.INFORMATION,
					LogState.AUTHENTICATE, LogLevel.LOW);
			byte[] octets = new byte[24];
			for (int i = 0; i < octets.length; i++) {
				octets[i] = keydata[i];
			}
			keydata = octets;
			Log.addEntry(
					"Function KDF(k, c): AES-192 key created: "
							+ HelperClass
									.toHexString(keydata),
					LogType.INFORMATION,
					LogState.AUTHENTICATE, LogLevel.LOW);
		} else if (algorithm.equals(Algorithms._AES_256)) {
			keydata = h(data, "SHA-256");
			Log.addEntry(
					"Function KDF(k, c): Will take hash as key for AES-256 usage directly: "
							+ HelperClass
									.toHexString(keydata),
					LogType.INFORMATION,
					LogState.AUTHENTICATE, LogLevel.LOW);
		}

		return keydata;

	}

	/**
	 * This method convert pi before it's used in KDF(...)
	 * 
	 * @param input
	 *            shared secret pi
	 * @param pwType
	 *            type of pi (pin/can)
	 * @return converted pi
	 * @throws PACEFunctionsException
	 */
	public static byte[] f(String input,
			PasswordTypes pwType)
			throws PACEFunctionsException {

		switch (pwType) {
		case PIN:
			return charTo8859_1(input);
		case CAN:
			return charTo8859_1(input);
		default:
			throw new PACEFunctionsException(
					"Function F(input): Password type not supported",
					LogState.AUTHENTICATE);
		}
	}

	/**
	 * Converts a char array into the ISO-8859-1 charset
	 * 
	 * @param input
	 *            data that need be converted
	 * @return converted bytes
	 * @throws PACEFunctionsException
	 */
	private static byte[] charTo8859_1(String input)
			throws PACEFunctionsException {
		Log.addEntry(
				"charTo8859_1(input): Converting input to ISO-8859-1 charset. Input: "
						+ input, LogType.INFORMATION,
				LogState.AUTHENTICATE, LogLevel.LOW);

		Charset iso88591charset = Charset
				.forName("ISO-8859-1");

		char inputChars[] = input.toCharArray();
		byte[] outputData = new byte[0];

		// convert each character to an octet using the ISO/IEC 8859-1 character
		// set
		for (int i = 0; i < inputChars.length; i++) {
			char[] oneChar = { inputChars[i] }; // actual character

			CharBuffer data = CharBuffer.wrap(oneChar);
			ByteBuffer outputBuffer = iso88591charset
					.encode(data);

			// copy new byte to existing converted bytes
			byte[] outputDataTmp = outputData;
			outputData = new byte[outputDataTmp.length + 1];

			for (int j = 0; j < outputDataTmp.length; j++) {
				outputData[j] = outputDataTmp[j];
			}

			// Check last byte
			outputData[outputData.length - 1] = outputBuffer
					.get();
			if (!isCharTo8859_1CodeValid(outputData[outputData.length - 1])) {
				throw new PACEFunctionsException(
						"charTo8859_1(input): Wrong character used",
						LogState.AUTHENTICATE);
			}

		}
		Log.addEntry(
				"charTo8859_1 Output: "
						+ HelperClass
								.toHexString(outputData),
				LogType.INFORMATION, LogState.AUTHENTICATE,
				LogLevel.LOW);

		return outputData;
	}

	/**
	 * Checks if character code is valid. The character codes 0x00-0x1F and
	 * 0x7F-0x9F are unassigned and MUST NOT be used.
	 * 
	 * @param code
	 *            character to check
	 * @return valid or not valid
	 */
	private static boolean isCharTo8859_1CodeValid(byte code) {

		if ((code >= 0x00 && code <= 0x1F)
				|| (code >= 0x7F && code <= 0x9F)) {
			return false;
		}
		return true;
	}

	/**
	 * This method encrypts nonce s by using Kpi
	 * 
	 * @param kpi
	 *            derived Pi
	 * @param s
	 *            nonce s
	 * @param algorithm
	 *            algorithm to use
	 * @return encrypted nonce z
	 * @throws PACEFunctionsException
	 */
	public static byte[] e(byte[] kpi, byte[] s,
			Algorithms algorithm)
			throws PACEFunctionsException {

		Log.addEntry(
				"e(kpi, plainText): Starting encryption of \""
						+ HelperClass.toHexString(s)
						+ "\"  by using key \""
						+ HelperClass.toHexString(kpi)
						+ "\"", LogType.INFORMATION,
				LogState.AUTHENTICATE, LogLevel.LOW);

		byte[] z = null;
		if (algorithm.equals(Algorithms._3DES_112)) {
			Log.addEntry(
					"e(kpi, plainText): Using 3DES ...",
					LogType.INFORMATION,
					LogState.AUTHENTICATE, LogLevel.LOW);
			try {
				z = CryptFunctions.TripleDES(kpi, s,
						new byte[8], true,
						LogState.AUTHENTICATE);
			} catch (CryptoException e1) {
				throw new PACEFunctionsException(
						"e(kpi, plainText): Could not encrypt using 3DES",
						LogState.AUTHENTICATE);
			}
			return z;

		} else {
			Log.addEntry(
					"e(kpi, plainText): Using AES ...",
					LogType.INFORMATION,
					LogState.AUTHENTICATE, LogLevel.LOW);
			try {
				z = CryptFunctions.AES(kpi, s,
						new byte[16], true,
						LogState.AUTHENTICATE);
			} catch (CryptoException e1) {
				throw new PACEFunctionsException(
						"e(kpi, plainText): Could not encrypt using AES",
						LogState.AUTHENTICATE);
			}
		}

		Log.addEntry(
				"e(kpi, plainText): Encryption done! Ciphertext: "
						+ HelperClass.toHexString(z),
				LogType.INFORMATION, LogState.AUTHENTICATE,
				LogLevel.LOW);

		return z;

	}

	/**
	 * This method decrypts nonce z by using Kpi
	 * 
	 * @param kpi
	 *            derived Pi
	 * @param z
	 *            encrypted nonce
	 * @param algorithm
	 *            algorithm to use
	 * @return decrypted nonce s
	 * @throws PACEFunctionsException
	 */
	public static byte[] d(byte[] kpi, byte[] z,
			Algorithms algorithm)
			throws PACEFunctionsException {

		Log.addEntry(
				"d(kpi, cipherText): Starting decryption of \""
						+ HelperClass.toHexString(z)
						+ "\"  by using key \""
						+ HelperClass.toHexString(kpi)
						+ "\"", LogType.INFORMATION,
				LogState.AUTHENTICATE, LogLevel.LOW);

		byte[] s = null;
		if (algorithm.equals(Algorithms._3DES_112)) {
			Log.addEntry(
					"d(kpi, cipherText): Using 3DES ...",
					LogType.INFORMATION,
					LogState.AUTHENTICATE, LogLevel.LOW);

			try {
				s = CryptFunctions.TripleDES(kpi, z,
						new byte[8], false,
						LogState.AUTHENTICATE);
			} catch (CryptoException e) {
				throw new PACEFunctionsException(
						"d(kpi, cipherText): Could not decrypt using 3DES",
						LogState.AUTHENTICATE);
			}

		} else {
			Log.addEntry(
					"d(kpi, cipherText): Using AES ...",
					LogType.INFORMATION,
					LogState.AUTHENTICATE, LogLevel.LOW);
			try {
				s = CryptFunctions.AES(kpi, z,
						new byte[16], false,
						LogState.AUTHENTICATE);
			} catch (CryptoException e) {
				throw new PACEFunctionsException(
						"d(kpi, cipherText): Could not decrypt using AES",
						LogState.AUTHENTICATE);
			}
		}

		Log.addEntry(
				"d(kpi, cipherText): Decryption done! Plaintext: "
						+ HelperClass.toHexString(s),
				LogType.INFORMATION, LogState.AUTHENTICATE,
				LogLevel.LOW);

		return s;

	}

	/**
	 * This method creates a CMAC of data by using a specific key. The output
	 * data will be used as authentication token.
	 * 
	 * @param key
	 *            K_MAC, which was derived from the key agreement
	 * @param data
	 *            public key data object
	 * @param algorithm
	 *            algorithm to use
	 * @return authentication token
	 */
	public static byte[] mac(byte[] key, byte[] data,
			Algorithms algorithm) {
		if (algorithm.equals(Algorithms._3DES_112)) {
			return CryptFunctions.TripleDES_MAC(key, data);
		} else {
			return CryptFunctions.AES_MAC(key, data);
		}
	}
}
