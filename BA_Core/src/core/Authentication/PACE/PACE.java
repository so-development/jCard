package core.Authentication.PACE;

import java.io.IOException;
import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.agreement.DHBasicAgreement;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.generators.DHKeyPairGenerator;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DHKeyGenerationParameters;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECKeyGenerationParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;

import core.Authentication.ASN1.PACEObjectIdentifiers;
import core.Authentication.ASN1.PublicKeyDataObjectDH;
import core.Authentication.ASN1.PublicKeyDataObjectEC;
import core.Communication.JCard;
import core.Exceptions.ConnectionException;
import core.Exceptions.InvalidActionException;
import core.Exceptions.InvalidCAPDUException;
import core.Exceptions.InvalidRAPDUException;
import core.Exceptions.PACEFunctionsException;
import core.Exceptions.PACERuntimeException;
import core.Exceptions.SecureMessagingException;
import core.Logging.Log;
import core.Logging.LogLevel;
import core.Logging.LogState;
import core.Logging.LogType;
import core.Management.KeyManagement;
import core.Support.HelperClass;

/**
 * This class represents all needed data and methods to run PACE
 * 
 * @author Mark Forjahn
 * 
 */
public abstract class PACE {

	protected JCard jcard; // API connection
	protected Algorithms algorithm = null; // current used algorithm
	protected PasswordTypes pwType = null; // current used shared secret as pi
	protected DomainParameter dp = null; // current standardized domain
											// parameter
	protected KeyManagement keyManagement; // contains pin as well as current
											// can

	protected AsymmetricKeyParameter x1 = null; // first own private key
	protected AsymmetricKeyParameter X1 = null; // first own public key
	protected AsymmetricKeyParameter x2 = null; // second own private key
	protected AsymmetricKeyParameter X2 = null; // second own public key

	protected AsymmetricKeyParameter Y1 = null; // first public key of opposite
												// side
	protected AsymmetricKeyParameter Y2 = null; // second public key of opposite
												// side

	protected byte[] nonce_s = null; // nonce s
	protected byte[] nonce_encrypted_z = null; // encrypted nonce s

	protected byte[] sharedSecret_K = null; // shared secret K
	protected byte[] sharedSecret_K_ENC = null; // derived shared secret K_ENC
												// for secure messaging
	protected byte[] sharedSecret_K_MAC = null; // derived shared secret K_MAC
												// for secure messaging

	protected byte[] authentikationTokenX = null; // own authentication token
	protected byte[] authentikationTokenY = null; // opposite authentication
													// token

	public PACE(JCard jcard, KeyManagement keyManagement) {
		this.jcard = jcard; // API connection
		this.keyManagement = keyManagement; // contains pin and can
	}

	/**
	 * To be implemented on both sides. PCD: Read out EF.CardAccess PICC:
	 * Transmit EF.CardAccess file
	 * 
	 * @throws PACERuntimeException
	 */
	public abstract void efCardAccess_message()
			throws PACERuntimeException;

	/**
	 * To be implemented on both sides. PCD: Send MSE:Set AT command PICC:
	 * receive command and set configuration
	 * 
	 * @throws PACERuntimeException
	 */
	public abstract void commandMSESetAT()
			throws PACERuntimeException;

	/**
	 * To be implemented on both sides. PCD: Request encrypted nonce PICC:
	 * transmit created (encrypted) nonce
	 * 
	 * @throws PACERuntimeException
	 */
	public abstract void commandGetNonce()
			throws PACERuntimeException,
			PACEFunctionsException;

	/**
	 * Same procedure on both sides. Method processes command "Map Nonce" ->
	 * Both sides create a first key pair x1 (private key) and X1 (public key)
	 * -> The public key X1 will then be sent and as Y1 on the opposite side
	 * received
	 * 
	 * @throws PACERuntimeException
	 */
	public void commandMapNonce()
			throws PACERuntimeException {
		Log.addEntry("Generating first key pair ...",
				LogType.INFORMATION, LogState.AUTHENTICATE,
				LogLevel.LOW);

		if (this.dp.getType().equals(DPTypes.DH)) {
			AsymmetricCipherKeyPair pair = createNewKeyPair();
			x1 = (DHPrivateKeyParameters) pair.getPrivate();
			X1 = (DHPublicKeyParameters) pair.getPublic();
			Log.addEntry(
					"First private key: "
							+ HelperClass
									.toHexString(((DHPrivateKeyParameters) pair
											.getPrivate())
											.getX()
											.toByteArray()),
					LogType.INFORMATION,
					LogState.AUTHENTICATE, LogLevel.LOW);
			Log.addEntry(
					"First public key: "
							+ HelperClass
									.toHexString(((DHPublicKeyParameters) pair
											.getPublic())
											.getY()
											.toByteArray()),
					LogType.INFORMATION,
					LogState.AUTHENTICATE, LogLevel.LOW);
		} else {

			AsymmetricCipherKeyPair pair = createNewKeyPair();
			x1 = (ECPrivateKeyParameters) pair.getPrivate();
			X1 = (ECPublicKeyParameters) pair.getPublic();
			Log.addEntry(
					"First private key: "
							+ HelperClass
									.toHexString(((ECPrivateKeyParameters) pair
											.getPrivate())
											.getD()
											.toByteArray()),
					LogType.INFORMATION,
					LogState.AUTHENTICATE, LogLevel.LOW);
			Log.addEntry(
					"First public key: "
							+ HelperClass
									.toHexString(((ECPublicKeyParameters) pair
											.getPublic())
											.getQ()
											.getEncoded()),
					LogType.INFORMATION,
					LogState.AUTHENTICATE, LogLevel.LOW);
		}

		try {
			commandMapNonce_send();
		} catch (InvalidCAPDUException e) {
			throw new PACERuntimeException(e.getMessage(),
					LogState.AUTHENTICATE);
		} catch (InvalidRAPDUException e) {
			throw new PACERuntimeException(e.getMessage(),
					LogState.AUTHENTICATE);
		} catch (InvalidActionException e) {
			throw new PACERuntimeException(e.getMessage(),
					LogState.AUTHENTICATE);
		} catch (ConnectionException e) {
			throw new PACERuntimeException(e.getMessage(),
					LogState.AUTHENTICATE);
		} catch (IOException e) {
			throw new PACERuntimeException(e.getMessage(),
					LogState.AUTHENTICATE);
		} catch (SecureMessagingException e) {
			throw new PACERuntimeException(e.getMessage(),
					LogState.AUTHENTICATE);
		}

		mapping();
	}

	/**
	 * Same procedure on both sides. Method processes command
	 * "Perform Key Agreement" -> Both sides create a second key pair x2
	 * (private key) and X2 (public key) -> The public key X2 will then be sent
	 * and as Y2 on the opposite side received
	 * 
	 * @throws PACERuntimeException
	 */
	public void commandPerformKeyAgreement()
			throws PACERuntimeException {

		Log.addEntry("Generating second key pair ...",
				LogType.INFORMATION, LogState.AUTHENTICATE,
				LogLevel.LOW);

		if (this.dp.getType().equals(DPTypes.DH)) {
			AsymmetricCipherKeyPair pair = createNewKeyPair();
			x2 = (DHPrivateKeyParameters) pair.getPrivate();
			X2 = (DHPublicKeyParameters) pair.getPublic();
			Log.addEntry(
					"Second private key: "
							+ HelperClass
									.toHexString(((DHPrivateKeyParameters) pair
											.getPrivate())
											.getX()
											.toByteArray()),
					LogType.INFORMATION,
					LogState.AUTHENTICATE, LogLevel.LOW);
			Log.addEntry(
					"Second public key: "
							+ HelperClass
									.toHexString(((DHPublicKeyParameters) pair
											.getPublic())
											.getY()
											.toByteArray()),
					LogType.INFORMATION,
					LogState.AUTHENTICATE, LogLevel.LOW);
		} else {
			AsymmetricCipherKeyPair pair = createNewKeyPair();
			x2 = (ECPrivateKeyParameters) pair.getPrivate();
			X2 = (ECPublicKeyParameters) pair.getPublic();
			Log.addEntry(
					"Second private key: "
							+ HelperClass
									.toHexString(((ECPrivateKeyParameters) pair
											.getPrivate())
											.getD()
											.toByteArray()),
					LogType.INFORMATION,
					LogState.AUTHENTICATE, LogLevel.LOW);
			Log.addEntry(
					"Second public key: "
							+ HelperClass
									.toHexString(((ECPublicKeyParameters) pair
											.getPublic())
											.getQ()
											.getEncoded()),
					LogType.INFORMATION,
					LogState.AUTHENTICATE, LogLevel.LOW);
		}

		try {
			commandPerformKeyAgreement_send();
		} catch (InvalidCAPDUException e) {
			throw new PACERuntimeException(e.getMessage(),
					LogState.AUTHENTICATE);
		} catch (InvalidRAPDUException e) {
			throw new PACERuntimeException(e.getMessage(),
					LogState.AUTHENTICATE);
		} catch (InvalidActionException e) {
			throw new PACERuntimeException(e.getMessage(),
					LogState.AUTHENTICATE);
		} catch (ConnectionException e) {
			throw new PACERuntimeException(e.getMessage(),
					LogState.AUTHENTICATE);
		} catch (IOException e) {
			throw new PACERuntimeException(e.getMessage(),
					LogState.AUTHENTICATE);
		} catch (SecureMessagingException e) {
			throw new PACERuntimeException(e.getMessage(),
					LogState.AUTHENTICATE);
		}
	}

	/**
	 * Same procedure on both sides. Method is called as mapping-process for the
	 * command "Map nonce" It's the basis for the command
	 * "Perform Key Agreement"
	 * 
	 * @throws PACERuntimeException
	 */
	private void mapping() throws PACERuntimeException {
		if (this.dp.getType().equals(DPTypes.DH)) {
			Log.addEntry(
					"Calculating DH shared secret ...",
					LogType.INFORMATION,
					LogState.AUTHENTICATE, LogLevel.LOW);

			DHBasicAgreement agreement = new DHBasicAgreement();
			agreement.init(x1);
			BigInteger secret = agreement
					.calculateAgreement(Y1);

			Log.addEntry(
					"DH shared secret: "
							+ HelperClass
									.toHexString(HelperClass
											.bigIntToByteArray(secret)),
					LogType.INFORMATION,
					LogState.AUTHENTICATE, LogLevel.LOW);
			Log.addEntry("Starting mapping ...",
					LogType.INFORMATION,
					LogState.AUTHENTICATE, LogLevel.LOW);

			// g' = ((g^s) % p) * secret % p
			BigInteger g_DH = dp
					.getDHParameter()
					.getG()
					.modPow(HelperClass
							.byteArrayToBigInteger(nonce_s),
							dp.getDHParameter().getP())
					.multiply(secret)
					.mod(dp.getDHParameter().getP());
			Log.addEntry(
					"Mapping finished! Generated g': "
							+ HelperClass.toHexString(g_DH
									.toByteArray()),
					LogType.INFORMATION,
					LogState.AUTHENTICATE, LogLevel.LOW);

			dp.setNewG(g_DH);
			Log.addEntry(
					"g' replaced g in domain parameters!",
					LogType.INFORMATION,
					LogState.AUTHENTICATE, LogLevel.LOW);
		} else {
			Log.addEntry(
					"Calculating ECDH shared secret ...",
					LogType.INFORMATION,
					LogState.AUTHENTICATE, LogLevel.LOW);

			ECDHBasicAgreement agreement = new ECDHBasicAgreement();
			agreement.init(x1);
			BigInteger secret = agreement
					.calculateAgreement(Y1);

			Log.addEntry(
					"ECDH shared secret: "
							+ HelperClass
									.toHexString(HelperClass
											.bigIntToByteArray(secret)),
					LogType.INFORMATION,
					LogState.AUTHENTICATE, LogLevel.LOW);
			Log.addEntry("Starting mapping ...",
					LogType.INFORMATION,
					LogState.AUTHENTICATE, LogLevel.LOW);

			// g' = g * s + secret
			ECPoint g_ECDH = dp
					.getECParameter()
					.getG()
					.multiply(
							HelperClass
									.byteArrayToBigInteger(nonce_s))
					.add(HelperClass.bytesToECPoint(
							secret.toByteArray(),
							(org.bouncycastle.math.ec.ECCurve.Fp) dp
									.getECParameter()
									.getCurve()));
			Log.addEntry(
					"Mapping finished! Generated g': "
							+ HelperClass
									.toHexString(g_ECDH
											.getEncoded()),
					LogType.INFORMATION,
					LogState.AUTHENTICATE, LogLevel.LOW);

			dp.setNewG(g_ECDH);
			Log.addEntry(
					"g' replaced g in domain parameters!",
					LogType.INFORMATION,
					LogState.AUTHENTICATE, LogLevel.LOW);
		}

	}

	/**
	 * Same procedure on both sides. Method is called to generate the shared
	 * secret K and its derived keys K_ENC and K_MAC
	 * 
	 * @throws PACERuntimeException
	 */
	public void generateSharedSecretK()
			throws PACERuntimeException,
			PACEFunctionsException {
		Log.addEntry("Calculating shared secret 'K' ...",
				LogType.INFORMATION, LogState.AUTHENTICATE,
				LogLevel.LOW);

		if (this.dp.getType().equals(DPTypes.DH)) {
			DHBasicAgreement agreement = new DHBasicAgreement();
			agreement.init(x2);
			sharedSecret_K = agreement.calculateAgreement(
					Y2).toByteArray();
		} else {
			ECDHBasicAgreement agreement = new ECDHBasicAgreement();
			agreement.init(x2);
			sharedSecret_K = agreement.calculateAgreement(
					Y2).toByteArray();
		}
		Log.addEntry(
				"Shared Secret K: "
						+ HelperClass
								.toHexString(sharedSecret_K),
				LogType.INFORMATION, LogState.AUTHENTICATE,
				LogLevel.LOW);

		Log.addEntry("Creating key 'K_ENC'",
				LogType.INFORMATION, LogState.AUTHENTICATE,
				LogLevel.LOW);
		sharedSecret_K_ENC = PACEFunctions.kdf(
				sharedSecret_K, 1, algorithm);
		Log.addEntry(
				"Key 'K_ENC': "
						+ HelperClass
								.toHexString(sharedSecret_K_ENC),
				LogType.INFORMATION, LogState.AUTHENTICATE,
				LogLevel.LOW);

		Log.addEntry("Creating key 'K_MAC'",
				LogType.INFORMATION, LogState.AUTHENTICATE,
				LogLevel.LOW);
		sharedSecret_K_MAC = PACEFunctions.kdf(
				sharedSecret_K, 2, algorithm);
		Log.addEntry(
				"Key 'K_MAC': "
						+ HelperClass
								.toHexString(sharedSecret_K_MAC),
				LogType.INFORMATION, LogState.AUTHENTICATE,
				LogLevel.LOW);
	}

	/**
	 * Same procedure on both sides. Method processes command
	 * "Mutual Authentication" -> Both sides create an authentication token
	 * 
	 * @throws PACERuntimeException
	 */
	public void commandMutualAuthentication()
			throws PACERuntimeException {

		Log.addEntry("Create authentication token ... ",
				LogType.INFORMATION, LogState.AUTHENTICATE,
				LogLevel.LOW);
		if (this.dp.getType().equals(DPTypes.DH)) {
			// Create new public key data object for DH
			PublicKeyDataObjectDH publicKey = new PublicKeyDataObjectDH(
					getActualProtocolOID(),
					dp.getDHParameter(),
					((DHPublicKeyParameters) Y2).getY());

			// authenticate using generated secret K_MAC
			authentikationTokenX = PACEFunctions.mac(
					this.sharedSecret_K_MAC,
					publicKey.getEncoded(), algorithm);
		} else {
			// Create new public key data object for EC
			PublicKeyDataObjectEC publicKey = new PublicKeyDataObjectEC(
					getActualProtocolOID(),
					dp.getECParameter(),
					((ECPublicKeyParameters) Y2).getQ());

			// authenticate using generated secret K_MAC
			authentikationTokenX = PACEFunctions.mac(
					this.sharedSecret_K_MAC,
					publicKey.getEncoded(), algorithm);
		}

		Log.addEntry(
				"Authentication token created: "
						+ HelperClass
								.toHexString(authentikationTokenX),
				LogType.INFORMATION, LogState.AUTHENTICATE,
				LogLevel.LOW);

		try {
			commandMutualAuthentication_send();
		} catch (InvalidCAPDUException e) {
			throw new PACERuntimeException(e.getMessage(),
					LogState.AUTHENTICATE);
		} catch (InvalidRAPDUException e) {
			throw new PACERuntimeException(e.getMessage(),
					LogState.AUTHENTICATE);
		} catch (InvalidActionException e) {
			throw new PACERuntimeException(e.getMessage(),
					LogState.AUTHENTICATE);
		} catch (ConnectionException e) {
			throw new PACERuntimeException(e.getMessage(),
					LogState.AUTHENTICATE);
		} catch (IOException e) {
			throw new PACERuntimeException(e.getMessage(),
					LogState.AUTHENTICATE);
		} catch (SecureMessagingException e) {
			throw new PACERuntimeException(e.getMessage(),
					LogState.AUTHENTICATE);
		}
	}

	/**
	 * Same procedure on both sides. -> both sides need to check the received
	 * authentication token of the opposite side
	 * 
	 * @throws PACERuntimeException
	 */
	public void checkAuthenticationToken()
			throws PACERuntimeException {

		byte[] authentikationTokenY_Strich = null;

		if (this.dp.getType().equals(DPTypes.DH)) {
			PublicKeyDataObjectDH publicKey = new PublicKeyDataObjectDH(
					getActualProtocolOID(),
					dp.getDHParameter(),
					((DHPublicKeyParameters) X2).getY());
			authentikationTokenY_Strich = PACEFunctions
					.mac(this.sharedSecret_K_MAC,
							publicKey.getEncoded(),
							algorithm);
		} else {
			PublicKeyDataObjectEC publicKey = new PublicKeyDataObjectEC(
					getActualProtocolOID(),
					dp.getECParameter(),
					((ECPublicKeyParameters) X2).getQ());
			authentikationTokenY_Strich = PACEFunctions
					.mac(this.sharedSecret_K_MAC,
							publicKey.getEncoded(),
							algorithm);
		}

		if (!Arrays.areEqual(authentikationTokenY_Strich,
				authentikationTokenY)) {
			throw new PACERuntimeException(
					"Authentication failed: authentication token doesn't match!",
					LogState.AUTHENTICATE);
		} else {
			Log.addEntry("Authentication token match!",
					LogType.INFORMATION,
					LogState.AUTHENTICATE, LogLevel.LOW);
		}
	}

	public byte[] getK_ENC() {
		return this.sharedSecret_K_ENC;
	}

	public byte[] getK_MAC() {
		return this.sharedSecret_K_MAC;
	}

	public Algorithms getAlgorithm() {
		return this.algorithm;
	}

	/**
	 * Sets the actual PACE configuration with given parameters
	 * 
	 * @param oid
	 *            algorithm oid
	 * @param parameterId
	 *            domain parameter id
	 * @throws PACERuntimeException
	 */
	protected void setConfiguration(
			DERObjectIdentifier oid, int parameterId)
			throws PACERuntimeException {
		if (oid.equals(PACEObjectIdentifiers.id_PACE_DH_GM_3DES_CBC_CBC)
				|| oid.equals(PACEObjectIdentifiers.id_PACE_ECDH_GM_3DES_CBC_CBC)) {
			algorithm = Algorithms._3DES_112;
		} else if (oid
				.equals(PACEObjectIdentifiers.id_PACE_DH_GM_AES_CBC_CMAC_128)
				|| oid.equals(PACEObjectIdentifiers.id_PACE_ECDH_GM_AES_CBC_CMAC_128)) {
			algorithm = Algorithms._AES_128;
		} else if (oid
				.equals(PACEObjectIdentifiers.id_PACE_DH_GM_AES_CBC_CMAC_192)
				|| oid.equals(PACEObjectIdentifiers.id_PACE_ECDH_GM_AES_CBC_CMAC_192)) {
			algorithm = Algorithms._AES_192;
		} else if (oid
				.equals(PACEObjectIdentifiers.id_PACE_DH_GM_AES_CBC_CMAC_256)
				|| oid.equals(PACEObjectIdentifiers.id_PACE_ECDH_GM_AES_CBC_CMAC_256)) {
			algorithm = Algorithms._AES_256;
		}
		dp = new DomainParameter(parameterId);
	}

	/**
	 * @return the actual algorithm-/protocol oid
	 */
	protected DERObjectIdentifier getActualProtocolOID() {
		if (this.algorithm.equals(Algorithms._3DES_112)) {
			if (dp.getType().equals(DPTypes.DH)) {
				return PACEObjectIdentifiers.id_PACE_DH_GM_3DES_CBC_CBC;
			} else {
				return PACEObjectIdentifiers.id_PACE_ECDH_GM_3DES_CBC_CBC;
			}
		} else if (this.algorithm
				.equals(Algorithms._AES_128)) {
			if (dp.getType().equals(DPTypes.DH)) {
				return PACEObjectIdentifiers.id_PACE_DH_GM_AES_CBC_CMAC_128;
			} else {
				return PACEObjectIdentifiers.id_PACE_ECDH_GM_AES_CBC_CMAC_128;
			}
		} else if (this.algorithm
				.equals(Algorithms._AES_192)) {
			if (dp.getType().equals(DPTypes.DH)) {
				return PACEObjectIdentifiers.id_PACE_DH_GM_AES_CBC_CMAC_192;
			} else {
				return PACEObjectIdentifiers.id_PACE_ECDH_GM_AES_CBC_CMAC_192;
			}
		} else if (this.algorithm
				.equals(Algorithms._AES_256)) {
			if (dp.getType().equals(DPTypes.DH)) {
				return PACEObjectIdentifiers.id_PACE_DH_GM_AES_CBC_CMAC_256;
			} else {
				return PACEObjectIdentifiers.id_PACE_ECDH_GM_AES_CBC_CMAC_256;
			}
		}
		return null;
	}

	private AsymmetricCipherKeyPair createNewKeyPair() {
		if (dp.getType().equals(DPTypes.DH)) {
			DHKeyGenerationParameters params = new DHKeyGenerationParameters(
					new SecureRandom(), dp.getDHParameter());
			DHKeyPairGenerator keyGen = new DHKeyPairGenerator();
			keyGen.init(params);
			return keyGen.generateKeyPair();
		} else {
			ECKeyGenerationParameters params = new ECKeyGenerationParameters(
					new ECDomainParameters(dp
							.getECParameter().getCurve(),
							dp.getECParameter().getG(), dp
									.getECParameter()
									.getN()),
					new SecureRandom());
			ECKeyPairGenerator keyGen = new ECKeyPairGenerator();
			keyGen.init(params);
			return keyGen.generateKeyPair();
		}
	}

	protected abstract void efCardAccess_message_send()
			throws PACERuntimeException,
			InvalidCAPDUException, InvalidRAPDUException,
			InvalidActionException, ConnectionException,
			IOException, SecureMessagingException;

	protected abstract void commandMSESetAT_send()
			throws PACERuntimeException,
			InvalidCAPDUException, InvalidRAPDUException,
			InvalidActionException, ConnectionException,
			IOException, SecureMessagingException;

	protected abstract void commandGetNonce_send()
			throws PACERuntimeException,
			InvalidCAPDUException, InvalidRAPDUException,
			InvalidActionException, ConnectionException,
			IOException, SecureMessagingException;

	protected abstract void commandMapNonce_send()
			throws PACERuntimeException,
			InvalidCAPDUException, InvalidRAPDUException,
			InvalidActionException, ConnectionException,
			IOException, SecureMessagingException;

	protected abstract void commandPerformKeyAgreement_send()
			throws PACERuntimeException,
			InvalidCAPDUException, InvalidRAPDUException,
			InvalidActionException, ConnectionException,
			IOException, SecureMessagingException;

	protected abstract void commandMutualAuthentication_send()
			throws PACERuntimeException,
			InvalidCAPDUException, InvalidRAPDUException,
			InvalidActionException, ConnectionException,
			IOException, SecureMessagingException;

}
