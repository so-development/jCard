package core.ISO7816_4.SecureMessaging;

import java.io.IOException;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;

import core.Authentication.PACE.Algorithms;
import core.Crypto.CryptFunctions;
import core.Exceptions.CryptoException;
import core.Exceptions.InvalidCAPDUException;
import core.Exceptions.InvalidRAPDUException;
import core.Exceptions.SecureMessagingException;
import core.ISO7816_4.APDU;
import core.ISO7816_4.CAPDU;
import core.ISO7816_4.RAPDU;
import core.ISO7816_4.Responses;
import core.ISO7816_4.SecureMessaging.ASN1.DataObject;
import core.Logging.Log;
import core.Logging.LogLevel;
import core.Logging.LogState;
import core.Logging.LogType;
import core.Support.HelperClass;

/**
 * Encrypting/ Decrypting of R-/C-APDUs
 * 
 * @author Mark Forjahn
 * 
 */

public class SecureMessaging {
	private byte[] encKey;
	private byte[] macKey;
	private Algorithms algorithm;
	private byte[] ssc;
	private int blocksize = 0;

	public SecureMessaging(byte[] encKey, byte[] macKey,
			Algorithms algorithm) {
		this.encKey = encKey;
		this.macKey = macKey;
		this.algorithm = algorithm;

		if (algorithm.equals(Algorithms._3DES_112)) {
			blocksize = 8;
		} else {
			blocksize = 16;
		}
		ssc = new byte[blocksize];
		Log.addEntry("-SM- Blocksize set to " + blocksize,
				LogType.INFORMATION, LogState.AUTHENTICATE,
				LogLevel.LOW);
	}

	public RAPDU encryptRAPDU(RAPDU rapdu, LogState state)
			throws SecureMessagingException {
		RAPDU encryptedRAPDU = null;
		byte[] do_87 = null;
		byte[] do_8e = null;
		byte[] do_99 = null;

		try {
			if (rapdu.getData() != null) {
				Log.addEntry(
						"-SM- Create DO87 object by using data "
								+ HelperClass
										.toHexString(rapdu
												.getData()),
						LogType.INFORMATION, state,
						LogLevel.LOW);
				do_87 = buildDO87(rapdu.getData(), state);
				Log.addEntry("-SM- DO87 created: "
						+ HelperClass.toHexString(do_87),
						LogType.INFORMATION, state,
						LogLevel.LOW);
			}
			Log.addEntry(
					"-SM- Create DO99 object by using SW-bytes "
							+ HelperClass.toHexString(rapdu
									.getSW()),
					LogType.INFORMATION, state,
					LogLevel.LOW);
			do_99 = buildDO99(rapdu.getSW(), state);
			Log.addEntry("-SM- DO99 created: "
					+ HelperClass.toHexString(do_99),
					LogType.INFORMATION, state,
					LogLevel.LOW);

			Log.addEntry(
					"-SM- Create DO8E object to authenticate data ...",
					LogType.INFORMATION, state,
					LogLevel.LOW);
			do_8e = buildDO8E(rapdu, do_87, null, do_99,
					state);
			Log.addEntry("-SM- DO8E created: "
					+ HelperClass.toHexString(do_8e),
					LogType.INFORMATION, state,
					LogLevel.LOW);
		} catch (CryptoException e) {
			throw new SecureMessagingException(
					e.toString(), state);
		} catch (IOException e) {
			throw new SecureMessagingException(
					e.toString(), state);
		}

		// [Encrypted Data] | enc. SW | MAC -> Use as data of new RAPDU
		byte[] newData = null;
		if (do_87 != null) {
			newData = do_87;
			newData = HelperClass.concatenateByteArrays(
					newData, do_99);
		} else {
			newData = do_99;
		}
		newData = HelperClass.concatenateByteArrays(
				newData, do_8e);

		Log.addEntry(
				"-SM- Create new encrypted/ authenticated RAPDU...",
				LogType.INFORMATION, state, LogLevel.LOW);
		try {
			encryptedRAPDU = new RAPDU(newData,
					rapdu.getSW1(), rapdu.getSW2(), state);
		} catch (InvalidRAPDUException e) {
			throw new SecureMessagingException(
					e.toString(), state);
		}

		incrementSSC();
		return encryptedRAPDU;

	}

	public RAPDU decryptRAPDU(RAPDU rapdu, LogState state)
			throws SecureMessagingException {

		// If expected Secure Messaging data objects are missing, the MRTD chip
		// SHALL respond with status bytes 0x6987
		// If Secure Messaging data objects are incorrect, the MRTD chip SHALL
		// respond with status bytes 0x6988

		if (rapdu.getData() == null) {
			throw new SecureMessagingException(
					"RAPDU data must not be null", state);
		}

		ASN1InputStream inputStream = new ASN1InputStream(
				rapdu.getData());
		ASN1Primitive asn1 = null;

		byte[] do_8e = null;
		byte[] do_87 = null;
		byte[] do_99 = null;

		try {
			asn1 = inputStream.readObject();
		} catch (IOException e1) {
			try {
				inputStream.close();
			} catch (IOException e) {
			}
			throw new SecureMessagingException(
					"Could not read RAPDU", state);
		}
		while (asn1 != null) {

			try {
				int tagno = DataObject.getTagno(asn1
						.getEncoded());
				if (tagno == 0x87) {
					do_87 = asn1.getEncoded();
					Log.addEntry(
							"-SM- Received DO87 (encrypted data): "
									+ HelperClass
											.toHexString(do_87),
							LogType.INFORMATION, state,
							LogLevel.LOW);
				} else if (tagno == 0x99) {
					do_99 = asn1.getEncoded();
					Log.addEntry(
							"-SM- Received DO99 (SW): "
									+ HelperClass
											.toHexString(do_99),
							LogType.INFORMATION, state,
							LogLevel.LOW);
				} else if (tagno == 0x8e) {
					do_8e = asn1.getEncoded();
					Log.addEntry(
							"-SM- Received DO8E (MAC): "
									+ HelperClass
											.toHexString(do_8e),
							LogType.INFORMATION, state,
							LogLevel.LOW);
				}
				asn1 = inputStream.readObject();
			} catch (IOException e1) {
			}

		}
		try {
			inputStream.close();
		} catch (IOException e1) {
		}

		if (do_8e == null) {
			throw new SecureMessagingException(
					"Could not find 0x8E tag - data not authenticated",
					state);
		}

		if (do_99 == null) {
			throw new SecureMessagingException(
					"Could not find 0x99 tag", state);
		}

		Log.addEntry("-SM- Checking received MAC ...",
				LogType.INFORMATION, state, LogLevel.LOW);
		byte[] received_mac = null;
		byte[] generated_do_8e = null;
		byte[] generated_mac = null;
		try {
			received_mac = DataObject
					.convertDERToBytes(do_8e);
			generated_do_8e = buildDO8E(rapdu, do_87, null,
					do_99, state);
			generated_mac = DataObject
					.convertDERToBytes(generated_do_8e);
		} catch (IOException e) {
			throw new SecureMessagingException(
					"Error while checking DO8E: "
							+ e.toString(), state);
		}
		if (!HelperClass.toHexString(received_mac).equals(
				HelperClass.toHexString(generated_mac))) {
			throw new SecureMessagingException(
					"DO8E object does not match - wrong key 'K_MAC' ?",
					state);
		} else {
			Log.addEntry(
					"-SM- Received MAC (DO8E) is fine!",
					LogType.INFORMATION, state,
					LogLevel.LOW);
		}

		byte[] decryptedData = null;
		byte[] sw = null;
		byte[] iv = null;

		if (do_87 != null) {
			Log.addEntry(
					"-SM- Decrypting data (DO87) now...",
					LogType.INFORMATION, state,
					LogLevel.LOW);
			try {
				if (algorithm.equals(Algorithms._3DES_112)) {
					iv = CryptFunctions.TripleDES(encKey,
							ssc, new byte[blocksize], true,
							state);
					decryptedData = CryptFunctions
							.TripleDES(
									encKey,
									DataObject
											.convertDERToBytes(do_87),
									iv, false, state);
				} else {
					iv = CryptFunctions.AES(encKey, ssc,
							new byte[blocksize], true,
							state);
					decryptedData = CryptFunctions
							.AES(encKey,
									DataObject
											.convertDERToBytes(do_87),
									iv, false, state);
				}
			} catch (CryptoException e) {
				throw new SecureMessagingException(
						"Could not decrypt received data: "
								+ e.toString(), state);
			} catch (IOException e) {
				throw new SecureMessagingException(
						"Could not decrypt received data: "
								+ e.toString(), state);
			}
			Log.addEntry(
					"-SM- Decrypted data: "
							+ HelperClass
									.toHexString(decryptedData),
					LogType.INFORMATION, state,
					LogLevel.LOW);
			decryptedData = removePadding(decryptedData,
					state);
		}

		try {
			Log.addEntry(
					"-SM- Getting SW bytes of DO99 now ... ",
					LogType.INFORMATION, state,
					LogLevel.LOW);
			sw = DataObject.convertDERToBytes(do_99);
			Log.addEntry(
					"-SM- SW bytes: "
							+ HelperClass
									.toHexString(do_99),
					LogType.INFORMATION, state,
					LogLevel.LOW);
		} catch (IOException e) {
			throw new SecureMessagingException(
					"Could not receive SW bytes: "
							+ e.toString(), state);
		}

		RAPDU decryptedRAPDU = null;

		Log.addEntry("-SM- Create new decrypted RAPDU ...",
				LogType.INFORMATION, state, LogLevel.LOW);
		try {
			decryptedRAPDU = new RAPDU(decryptedData, sw,
					state);
		} catch (InvalidRAPDUException e) {
			throw new SecureMessagingException(
					"Could not create new decrypted rapdu: "
							+ e.toString(), state);
		}

		incrementSSC();
		return decryptedRAPDU;
	}

	public CAPDU encryptCAPDU(CAPDU capdu, LogState state)
			throws SecureMessagingException {
		byte[] do_8e = null;
		byte[] do_87 = null;
		byte[] do_97 = null;

		Log.addEntry("-SM- Add SM-CLA -tag (0xXC) ... ",
				LogType.INFORMATION, state, LogLevel.LOW);
		Log.addEntry(
				"-SM- 'Old' CLA:"
						+ HelperClass.toHexString(capdu
								.getCLA()),
				LogType.INFORMATION, state, LogLevel.LOW);
		byte smCLA = capdu.getCLA();
		smCLA |= 0x0C;
		Log.addEntry(
				"-SM- 'New' CLA:"
						+ HelperClass.toHexString(smCLA),
				LogType.INFORMATION, state, LogLevel.LOW);

		try {
			capdu = new CAPDU(smCLA, capdu.getINS(),
					capdu.getP1(), capdu.getP2(),
					capdu.getData(), capdu.getLe(), state);
		} catch (InvalidCAPDUException e) {
			throw new SecureMessagingException(
					"Could not set new CLA: "
							+ e.toString(), state);
		}

		try {
			if (capdu.getData() != null) {
				Log.addEntry(
						"-SM- Create DO87 object by using data "
								+ HelperClass
										.toHexString(capdu
												.getData()),
						LogType.INFORMATION, state,
						LogLevel.LOW);
				do_87 = buildDO87(capdu.getData(), state);
				Log.addEntry("-SM- DO87 created: "
						+ HelperClass.toHexString(do_87),
						LogType.INFORMATION, state,
						LogLevel.LOW);
			}
			if (capdu.getLe() != 0x00) {
				Log.addEntry(
						"-SM- Create DO97 object by using Le "
								+ HelperClass
										.toHexString(capdu
												.getLe()),
						LogType.INFORMATION, state,
						LogLevel.LOW);
				do_97 = buildDO97(capdu.getLe(), state);
				Log.addEntry("-SM- DO97 created: "
						+ HelperClass.toHexString(do_97),
						LogType.INFORMATION, state,
						LogLevel.LOW);
			}

			Log.addEntry(
					"-SM- Create DO8E object to authenticate data ...",
					LogType.INFORMATION, state,
					LogLevel.LOW);
			do_8e = buildDO8E(capdu, do_87, do_97, null,
					state);
			Log.addEntry("-SM- DO8E created: "
					+ HelperClass.toHexString(do_8e),
					LogType.INFORMATION, state,
					LogLevel.LOW);

		} catch (CryptoException e) {
			throw new SecureMessagingException(
					e.toString(), state);
		} catch (IOException e) {
			throw new SecureMessagingException(
					e.toString(), state);
		}

		// [Encrypted Data] | [Le] | MAC -> As new data of CAPDU body
		byte[] newData = null;
		if (do_87 != null) {
			newData = do_87;
		}
		if (do_97 != null) {
			if (newData == null) {
				newData = do_97;
			} else {
				newData = HelperClass
						.concatenateByteArrays(newData,
								do_97);
			}
		}
		if (newData != null) {
			newData = HelperClass.concatenateByteArrays(
					newData, do_8e);
		} else {
			newData = do_8e;
		}

		Log.addEntry(
				"-SM- Create new encrypted/ authenticated CAPDU...",
				LogType.INFORMATION, state, LogLevel.LOW);
		CAPDU encryptedCAPDU = null;
		try {
			encryptedCAPDU = new CAPDU(capdu.getCLA(),
					capdu.getINS(), capdu.getP1(),
					capdu.getP2(), newData, (byte) 0x00,
					state);
		} catch (InvalidCAPDUException e) {
			throw new SecureMessagingException(
					e.toString(), state);
		}

		incrementSSC();
		return encryptedCAPDU;
	}

	public CAPDU decryptCAPDU(CAPDU capdu, LogState state)
			throws SecureMessagingException {

		if (capdu.getData() == null) {
			throw new SecureMessagingException(
					"CAPDU data must not be null", state);
		}

		ASN1InputStream inputStream = new ASN1InputStream(
				capdu.getData());
		ASN1Primitive asn1 = null;

		byte[] do_8e = null;
		byte[] do_87 = null;
		byte[] do_97 = null;

		try {
			asn1 = inputStream.readObject();
		} catch (IOException e1) {
			try {
				inputStream.close();
			} catch (IOException e) {
			}
			throw new SecureMessagingException(
					"Could not read CAPDU",
					Responses.SECURE_MESSAGING_MISSING_DATA_OBJECTS,
					state);
		}
		while (asn1 != null) {

			try {
				int tagno = DataObject.getTagno(asn1
						.getEncoded());
				if (tagno == 0x87) {
					do_87 = asn1.getEncoded();
					Log.addEntry(
							"-SM- Received DO87 (encrypted data): "
									+ HelperClass
											.toHexString(do_87),
							LogType.INFORMATION, state,
							LogLevel.LOW);
				} else if (tagno == 0x97) {
					do_97 = asn1.getEncoded();
					Log.addEntry(
							"-SM- Received DO97 (Le): "
									+ HelperClass
											.toHexString(do_97),
							LogType.INFORMATION, state,
							LogLevel.LOW);
				} else if (tagno == 0x8e) {
					do_8e = asn1.getEncoded();
					Log.addEntry(
							"-SM- Received DO8E (MAC): "
									+ HelperClass
											.toHexString(do_8e),
							LogType.INFORMATION, state,
							LogLevel.LOW);
				}
				asn1 = inputStream.readObject();
			} catch (IOException e1) {
			}

		}
		try {
			inputStream.close();
		} catch (IOException e1) {
		}

		if (do_8e == null) {
			throw new SecureMessagingException(
					"Could not find 0x8E Tag - data not authenticated",
					Responses.SECURE_MESSAGING_MISSING_DATA_OBJECTS,
					state);
		}

		Log.addEntry("-SM- Checking received MAC ...",
				LogType.INFORMATION, state, LogLevel.LOW);
		byte[] received_mac = null;
		byte[] generated_do_8e = null;
		byte[] generated_mac = null;
		try {
			received_mac = DataObject
					.convertDERToBytes(do_8e);
			generated_do_8e = buildDO8E(capdu, do_87,
					do_97, null, state);
			generated_mac = DataObject
					.convertDERToBytes(generated_do_8e);
		} catch (IOException e) {
			throw new SecureMessagingException(
					"Error while checking DO8E: "
							+ e.toString(),
					Responses.SECURE_MESSAGING_WRONG_DATA_OBJECTS,
					state);
		}

		if (!HelperClass.toHexString(received_mac).equals(
				HelperClass.toHexString(generated_mac))) {
			throw new SecureMessagingException(
					"DO8E object does not match - wrong key 'K_MAC' ?",
					state);
		} else {
			Log.addEntry(
					"-SM- Received MAC (DO8E) is fine!",
					LogType.INFORMATION, state,
					LogLevel.LOW);
		}

		byte[] decryptedData = null;
		byte[] le = null;

		byte[] iv = null;
		if (do_87 != null) {
			Log.addEntry(
					"-SM- Decrypting data (DO87) now...",
					LogType.INFORMATION, state,
					LogLevel.LOW);
			try {
				if (algorithm.equals(Algorithms._3DES_112)) {
					iv = CryptFunctions.TripleDES(encKey,
							ssc, new byte[blocksize], true,
							state);
					decryptedData = CryptFunctions
							.TripleDES(
									encKey,
									DataObject
											.convertDERToBytes(do_87),
									iv, false, state);
				} else {
					iv = CryptFunctions.AES(encKey, ssc,
							new byte[blocksize], true,
							state);
					decryptedData = CryptFunctions
							.AES(encKey,
									DataObject
											.convertDERToBytes(do_87),
									iv, false, state);
				}
			} catch (CryptoException e) {
				throw new SecureMessagingException(
						"Could not decrypt received data: "
								+ e.toString(),
						Responses.SECURE_MESSAGING_WRONG_DATA_OBJECTS,
						state);
			} catch (IOException e) {
				throw new SecureMessagingException(
						"Could not decrypt received data: "
								+ e.toString(),
						Responses.SECURE_MESSAGING_WRONG_DATA_OBJECTS,
						state);
			}
			Log.addEntry(
					"-SM- Decrypted data: "
							+ HelperClass
									.toHexString(decryptedData),
					LogType.INFORMATION, state,
					LogLevel.LOW);
			decryptedData = removePadding(decryptedData,
					state);
		}

		if (do_97 != null) {
			try {
				Log.addEntry(
						"-SM- Getting Le byte of DO97 now ... ",
						LogType.INFORMATION, state,
						LogLevel.LOW);
				le = DataObject.convertDERToBytes(do_97);
				Log.addEntry(
						"-SM- Le: "
								+ HelperClass
										.toHexString(le),
						LogType.INFORMATION, state,
						LogLevel.LOW);
			} catch (IOException e) {
				throw new SecureMessagingException(
						"Could not receive le: "
								+ e.toString(),
						Responses.SECURE_MESSAGING_WRONG_DATA_OBJECTS,
						state);
			}
		}

		Log.addEntry(
				"-SM- Removing SM-CLA -tag (0xXC) ... ",
				LogType.INFORMATION, state, LogLevel.LOW);
		Log.addEntry(
				"-SM- 'Old' CLA:"
						+ HelperClass.toHexString(capdu
								.getCLA()),
				LogType.INFORMATION, state, LogLevel.LOW);
		byte smCLA = capdu.getCLA();
		smCLA ^= 0x0C;
		Log.addEntry(
				"-SM- 'New' CLA:"
						+ HelperClass.toHexString(smCLA),
				LogType.INFORMATION, state, LogLevel.LOW);

		Log.addEntry("-SM- Create new decrypted CAPDU ...",
				LogType.INFORMATION, state, LogLevel.LOW);
		CAPDU decryptedCAPDU = null;

		if (le != null) {
			try {
				decryptedCAPDU = new CAPDU(smCLA,
						capdu.getINS(), capdu.getP1(),
						capdu.getP2(), decryptedData,
						le[0], state);
			} catch (InvalidCAPDUException e) {
				throw new SecureMessagingException(
						"Could not create new decrypted capdu: "
								+ e.toString(),
						Responses.SECURE_MESSAGING_WRONG_DATA_OBJECTS,
						state);
			}
		} else {
			try {
				decryptedCAPDU = new CAPDU(smCLA,
						capdu.getINS(), capdu.getP1(),
						capdu.getP2(), decryptedData, state);
			} catch (InvalidCAPDUException e) {
				throw new SecureMessagingException(
						"Could not create new decrypted capdu: "
								+ e.toString(),
						Responses.SECURE_MESSAGING_WRONG_DATA_OBJECTS,
						state);
			}
		}

		incrementSSC();
		return decryptedCAPDU;
	}

	private byte[] buildDO99(byte[] sw, LogState state)
			throws IOException {
		return DataObject.convertBytesToDER(sw, 0x99);
	}

	private byte[] buildDO97(byte le, LogState state)
			throws IOException {
		byte[] do_97 = DataObject.convertBytesToDER(le,
				0x97);
		return do_97;
	}

	private byte[] buildDO8E(APDU apdu, byte[] do_87,
			byte[] do_97, byte[] do_99, LogState state)
			throws IOException {

		byte[] mac_input_data = null;
		byte[] do_97_padded = null;
		byte[] do_99_padded = null;

		if (do_99 != null) {
			// RAPDU
			do_99_padded = addPadding(do_99, state);

			if (do_87 != null) {
				mac_input_data = HelperClass
						.concatenateByteArrays(ssc, do_87);
				mac_input_data = HelperClass
						.concatenateByteArrays(
								mac_input_data,
								do_99_padded);
			} else {
				mac_input_data = HelperClass
						.concatenateByteArrays(ssc,
								do_99_padded);
			}
			Log.addEntry(
					"-SM- MAC calculation of \""
							+ HelperClass
									.toHexString(mac_input_data)
							+ "\" (SSC + Formatted encrypted data + padded DO99) now running...",
					LogType.INFORMATION, state,
					LogLevel.LOW);
		} else {
			// CAPDU
			byte[] header_padded = addPadding(
					((CAPDU) apdu).getHeader(), state);
			mac_input_data = HelperClass
					.concatenateByteArrays(ssc,
							header_padded);
			if (do_97 != null) {
				do_97_padded = addPadding(do_97, state);

				if (do_87 != null) {
					// Padded Header + formatted encrypted data + padded Le
					mac_input_data = HelperClass
							.concatenateByteArrays(
									mac_input_data, do_87);
					mac_input_data = HelperClass
							.concatenateByteArrays(
									mac_input_data,
									do_97_padded);
				} else {
					// Padded Header + padded Le
					mac_input_data = HelperClass
							.concatenateByteArrays(
									mac_input_data,
									do_97_padded);
				}
			} else {
				if (do_87 != null) {
					// Padded Header + formatted encrypted data
					mac_input_data = HelperClass
							.concatenateByteArrays(
									mac_input_data, do_87);
				}
			}
			Log.addEntry(
					"-SM- MAC calculation of \""
							+ HelperClass
									.toHexString(mac_input_data)
							+ "\" (SSC + Padded header + formatted encrypted data (DO87) [+ Le (padded DO97)]) now running...",
					LogType.INFORMATION, state,
					LogLevel.LOW);
		}

		byte[] mac = null;

		if (algorithm.equals(Algorithms._3DES_112)) {
			mac = CryptFunctions.TripleDES_MAC(macKey,
					mac_input_data);
		} else {
			mac = CryptFunctions.AES_MAC(macKey,
					mac_input_data);
		}

		Log.addEntry(
				"-SM- MAC created: "
						+ HelperClass.toHexString(mac),
				LogType.INFORMATION, state, LogLevel.LOW);

		return DataObject.convertBytesToDER(mac, 0x8E);

	}

	private byte[] buildDO87(byte[] data, LogState state)
			throws CryptoException, IOException {

		byte[] iv = null;
		byte[] encryptedData = null;

		// PADDING:
		// The padding shall apply at the end of each data object to be
		// integrated followed either
		// by a data object not to be integrated or by no further data object.
		// ...
		// The padding consists of one mandatory byte valued to '80' followed,
		// if needed, by 0 to k-1
		// bytes set to '00', until the respective data block is filled up to k
		// bytes. Padding for
		// authentication has no influence on transmission as the padding bytes
		// shall not be transmitted.

		// The mode of operation is "cipher block chaining" (see ISO/IEC 10116).
		// The first input is the
		// exclusive-or of the initial check block with the first data block.

		// init iv

		data = addPadding(data, state);
		if (algorithm.equals(Algorithms._3DES_112)) {
			iv = CryptFunctions.TripleDES(encKey, ssc,
					new byte[blocksize], true, state);
			encryptedData = CryptFunctions.TripleDES(
					encKey, data, iv, true, state);
		} else {
			iv = CryptFunctions.AES(encKey, ssc,
					new byte[blocksize], true, state);
			encryptedData = CryptFunctions.AES(encKey,
					data, iv, true, state);
		}

		Log.addEntry(
				"-SM- Actual ssc: "
						+ HelperClass.toHexString(ssc),
				LogType.INFORMATION, state, LogLevel.LOW);
		Log.addEntry(
				"-SM- IV created (ssc encryted by using K_ENC): "
						+ HelperClass.toHexString(iv),
				LogType.INFORMATION, state, LogLevel.LOW);
		Log.addEntry(
				"-SM- Encrypted data (using K_ENC and generated iv): "
						+ HelperClass
								.toHexString(encryptedData),
				LogType.INFORMATION, state, LogLevel.LOW);

		return DataObject.convertBytesToDER(encryptedData,
				0x87);
	}

	private void incrementSSC() {
		for (int i = ssc.length - 1; i >= 0; i--) {
			ssc[i]++;
			if (ssc[i] != 0) {
				break;
			}
		}
	}

	private byte[] addPadding(byte[] data, LogState state) {
		Log.addEntry("-SM- Starting padding of "
				+ HelperClass.toHexString(data),
				LogType.INFORMATION, state, LogLevel.LOW);
		byte[] paddedData = new byte[data.length
				+ (blocksize - data.length % blocksize)];
		System.arraycopy(data, 0, paddedData, 0,
				data.length);
		paddedData[data.length] = (byte) 0x80;
		Log.addEntry(
				"-SM- Padded result: "
						+ HelperClass
								.toHexString(paddedData),
				LogType.INFORMATION, state, LogLevel.LOW);
		return paddedData;
	}

	private byte[] removePadding(byte[] data, LogState state) {
		Log.addEntry("-SM- Removing padding of "
				+ HelperClass.toHexString(data),
				LogType.INFORMATION, state, LogLevel.LOW);
		for (int i = data.length - 1; i >= 0; i--) {
			if (data[i] == (byte) 0x80) {
				byte[] bytes = new byte[i];
				System.arraycopy(data, 0, bytes, 0, i);
				Log.addEntry("-SM- Unpadded result: "
						+ HelperClass.toHexString(bytes),
						LogType.INFORMATION, state,
						LogLevel.LOW);
				return bytes;
			}
		}
		Log.addEntry(
				"-SM- Unpadded result: "
						+ HelperClass.toHexString(data),
				LogType.INFORMATION, state, LogLevel.LOW);
		return data;
	}

}
