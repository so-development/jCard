package Authentication;

import java.io.IOException;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECCurve.Fp;

import core.Authentication.ASN1.DynamicAuthenticationData;
import core.Authentication.ASN1.MSESetAT;
import core.Authentication.ASN1.PACEInfo;
import core.Authentication.PACE.Algorithms;
import core.Authentication.PACE.DPTypes;
import core.Authentication.PACE.DomainParameter;
import core.Authentication.PACE.PACE;
import core.Authentication.PACE.PACEFunctions;
import core.Authentication.PACE.PasswordTypes;
import core.Communication.JCard;
import core.Crypto.RandomCreator;
import core.Exceptions.SecretNotSetException;
import core.Exceptions.ConnectionException;
import core.Exceptions.InvalidActionException;
import core.Exceptions.InvalidCAPDUException;
import core.Exceptions.InvalidRAPDUException;
import core.Exceptions.PACEFunctionsException;
import core.Exceptions.PACERuntimeException;
import core.Exceptions.SecureMessagingException;
import core.ISO7816_4.CAPDU;
import core.ISO7816_4.RAPDU;
import core.Logging.Log;
import core.Logging.LogLevel;
import core.Logging.LogState;
import core.Logging.LogType;
import core.Management.KeyManagement;
import core.Support.HelperClass;

/**
 * PACE on PICC side
 * 
 * @author Mark Forjahn
 * 
 */
public class PICCPACE extends PACE {

	int standardizedDomainParameterID;

	public PICCPACE(JCard jcard,
			KeyManagement keyManagement,
			int standardizedDomainParameterID,
			Algorithms algorithm) {
		super(jcard, keyManagement);
		this.algorithm = algorithm;
		this.standardizedDomainParameterID = standardizedDomainParameterID;
	}

	@Override
	public void efCardAccess_message()
			throws PACERuntimeException {

		this.dp = new DomainParameter(
				standardizedDomainParameterID);
		try {
			efCardAccess_message_send();
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

	@Override
	public void commandMSESetAT()
			throws PACERuntimeException {
		try {
			commandMSESetAT_send();
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

	@Override
	public void commandGetNonce()
			throws PACERuntimeException,
			PACEFunctionsException {
		try {
			String pi = this.pwType
					.equals(PasswordTypes.PIN) ? keyManagement
					.getPIN().getKeyAsString()
					: keyManagement.getCAN()
							.getKeyAsString();

			byte[] kpi = PACEFunctions.kdf(
					PACEFunctions.f(pi, pwType), 3,
					algorithm);
			Log.addEntry(
					"Kpi derived: "
							+ HelperClass.toHexString(kpi),
					LogType.INFORMATION,
					LogState.AUTHENTICATE, LogLevel.LOW);

			nonce_s = RandomCreator
					.createSecureRandomBytes(128,
							LogState.AUTHENTICATE);
			Log.addEntry(
					"Nonce s created: "
							+ HelperClass
									.toHexString(nonce_s),
					LogType.INFORMATION,
					LogState.AUTHENTICATE, LogLevel.LOW);

			this.nonce_encrypted_z = PACEFunctions.e(kpi,
					nonce_s, algorithm);
			Log.addEntry(
					"Nonce s encyrpted: "
							+ HelperClass
									.toHexString(this.nonce_encrypted_z),
					LogType.INFORMATION,
					LogState.AUTHENTICATE, LogLevel.LOW);
		} catch (NoSuchAlgorithmException e) {
			throw new PACERuntimeException(
					"Could not create nonce s",
					LogState.AUTHENTICATE);
		} catch (SecretNotSetException e) {
			throw new PACERuntimeException(
					"Could not read shared secret",
					LogState.AUTHENTICATE);
		}

		try {
			commandGetNonce_send();
		} catch (InvalidRAPDUException e) {
			throw new PACERuntimeException(e.getMessage(),
					LogState.AUTHENTICATE);
		} catch (IOException e) {
			throw new PACERuntimeException(e.getMessage(),
					LogState.AUTHENTICATE);
		} catch (InvalidActionException e) {
			throw new PACERuntimeException(e.getMessage(),
					LogState.AUTHENTICATE);
		} catch (ConnectionException e) {
			throw new PACERuntimeException(e.getMessage(),
					LogState.AUTHENTICATE);
		} catch (InvalidCAPDUException e) {
			throw new PACERuntimeException(e.getMessage(),
					LogState.AUTHENTICATE);
		} catch (SecureMessagingException e) {
			throw new PACERuntimeException(e.getMessage(),
					LogState.AUTHENTICATE);
		}

	}

	@Override
	protected void efCardAccess_message_send()
			throws PACERuntimeException,
			InvalidCAPDUException, InvalidRAPDUException,
			InvalidActionException, ConnectionException,
			IOException, SecureMessagingException {

		Log.addEntry("Creating PACEInfo - oid: "
				+ getActualProtocolOID()
				+ "; Version: 2; parameterId: "
				+ standardizedDomainParameterID,
				LogType.INFORMATION, LogState.AUTHENTICATE,
				LogLevel.LOW);
		PACEInfo paceInfo = new PACEInfo(
				getActualProtocolOID(), 2,
				standardizedDomainParameterID);
		byte[] efcardaccess = paceInfo.getDEREncoded();

		Log.addEntry("Sending PACEInfo as DER: "
				+ HelperClass.toHexString(efcardaccess),
				LogType.INFORMATION, LogState.AUTHENTICATE,
				LogLevel.LOW);
		RAPDU rapdu = new RAPDU(efcardaccess, (byte) 0x90,
				(byte) 0x00, LogState.AUTHENTICATE);
		jcard.sendRAPDU(rapdu, LogState.AUTHENTICATE);

	}

	@Override
	protected void commandMSESetAT_send()
			throws PACERuntimeException,
			InvalidCAPDUException, InvalidRAPDUException,
			InvalidActionException, ConnectionException,
			IOException, SecureMessagingException {

		CAPDU capdu = (CAPDU) jcard
				.getLastReceivedData(LogState.AUTHENTICATE);
		MSESetAT msesetat = new MSESetAT(capdu.getData());
		Log.addEntry(
				"Recieved MSE:Set AT - protocol oid: "
						+ msesetat.getProtocolOID()
						+ "; shared secret type: "
						+ msesetat.getSharedKey()
						+ "; parameter id: "
						+ msesetat.getParameterId(),
				LogType.INFORMATION, LogState.AUTHENTICATE,
				LogLevel.LOW);

		setConfiguration(msesetat.getProtocolOID(),
				msesetat.getParameterId());
		this.pwType = msesetat.getSharedKey();

		RAPDU rapdu = new RAPDU((byte) 0x90, (byte) 0x00);
		jcard.sendRAPDU(rapdu, LogState.AUTHENTICATE);

	}

	@Override
	protected void commandGetNonce_send()
			throws PACERuntimeException,
			InvalidCAPDUException, InvalidRAPDUException,
			InvalidActionException, ConnectionException,
			IOException, SecureMessagingException {

		byte[] dad_Tag_80 = DynamicAuthenticationData
				.convertBytesToDER(0x80, nonce_encrypted_z);

		Log.addEntry("Sending encrypted nonce z as DER: "
				+ HelperClass.toHexString(dad_Tag_80),
				LogType.INFORMATION, LogState.AUTHENTICATE,
				LogLevel.LOW);
		RAPDU rapdu = new RAPDU(dad_Tag_80, (byte) 0x90,
				(byte) 0x00, LogState.AUTHENTICATE);
		jcard.sendRAPDU(rapdu, LogState.AUTHENTICATE);
	}

	@Override
	protected void commandMapNonce_send()
			throws PACERuntimeException,
			InvalidCAPDUException, InvalidRAPDUException,
			InvalidActionException, ConnectionException,
			IOException, SecureMessagingException {
		CAPDU capdu = (CAPDU) jcard
				.getLastReceivedData(LogState.AUTHENTICATE);

		byte[] Y1Bytes = DynamicAuthenticationData
				.convertDERToBytes(0x81, capdu.getData());
		byte[] dad_Tag_82 = null;
		if (Y1Bytes == null) {
			throw new PACERuntimeException(
					"Could not receive Y1",
					LogState.AUTHENTICATE);
		}
		if (this.dp.getType().equals(DPTypes.DH)) {
			Y1 = new DHPublicKeyParameters(new BigInteger(
					1, Y1Bytes), dp.getDHParameter());
			Log.addEntry(
					"Received public key Y1: "
							+ HelperClass
									.toHexString(((DHPublicKeyParameters) Y1)
											.getY()
											.toByteArray()),
					LogType.INFORMATION,
					LogState.AUTHENTICATE, LogLevel.LOW);
			dad_Tag_82 = DynamicAuthenticationData
					.convertBytesToDER(0x82,
							((DHPublicKeyParameters) X1)
									.getY().toByteArray());
		} else {
			Y1 = new ECPublicKeyParameters(
					HelperClass.bytesToECPoint(Y1Bytes,
							(Fp) dp.getECParameter()
									.getCurve()),
					new ECDomainParameters(dp
							.getECParameter().getCurve(),
							dp.getECParameter().getG(), dp
									.getECParameter()
									.getN()));
			Log.addEntry(
					"Received public key Y1: "
							+ HelperClass
									.toHexString(((ECPublicKeyParameters) Y1)
											.getQ()
											.getEncoded()),
					LogType.INFORMATION,
					LogState.AUTHENTICATE, LogLevel.LOW);
			dad_Tag_82 = DynamicAuthenticationData
					.convertBytesToDER(0x82,
							((ECPublicKeyParameters) X1)
									.getQ().getEncoded());
		}

		Log.addEntry("Sending public key X1 as DER: "
				+ HelperClass.toHexString(dad_Tag_82),
				LogType.INFORMATION, LogState.AUTHENTICATE,
				LogLevel.LOW);
		RAPDU rapdu = new RAPDU(dad_Tag_82, (byte) 0x90,
				(byte) 0x00, LogState.AUTHENTICATE);
		jcard.sendRAPDU(rapdu, LogState.AUTHENTICATE);

	}

	@Override
	protected void commandPerformKeyAgreement_send()
			throws PACERuntimeException,
			InvalidCAPDUException, InvalidRAPDUException,
			InvalidActionException, ConnectionException,
			IOException, SecureMessagingException {

		CAPDU capdu = (CAPDU) jcard
				.getLastReceivedData(LogState.AUTHENTICATE);

		byte[] Y2Bytes = DynamicAuthenticationData
				.convertDERToBytes(0x83, capdu.getData());
		byte[] dad_Tag_84 = null;

		if (Y2Bytes == null) {
			throw new PACERuntimeException(
					"Could not receive Y2",
					LogState.AUTHENTICATE);
		}
		if (this.dp.getType().equals(DPTypes.DH)) {
			Y2 = new DHPublicKeyParameters(new BigInteger(
					1, Y2Bytes), dp.getDHParameter());
			Log.addEntry(
					"Received public key Y2: "
							+ HelperClass
									.toHexString(((DHPublicKeyParameters) Y2)
											.getY()
											.toByteArray()),
					LogType.INFORMATION,
					LogState.AUTHENTICATE, LogLevel.LOW);
			dad_Tag_84 = DynamicAuthenticationData
					.convertBytesToDER(0x84,
							((DHPublicKeyParameters) X2)
									.getY().toByteArray());
		} else {
			Y2 = new ECPublicKeyParameters(
					HelperClass.bytesToECPoint(Y2Bytes,
							(Fp) dp.getECParameter()
									.getCurve()),
					new ECDomainParameters(dp
							.getECParameter().getCurve(),
							dp.getECParameter().getG(), dp
									.getECParameter()
									.getN()));
			Log.addEntry(
					"Received public key Y2: "
							+ HelperClass
									.toHexString(((ECPublicKeyParameters) Y2)
											.getQ()
											.getEncoded()),
					LogType.INFORMATION,
					LogState.AUTHENTICATE, LogLevel.LOW);
			dad_Tag_84 = DynamicAuthenticationData
					.convertBytesToDER(0x84,
							((ECPublicKeyParameters) X2)
									.getQ().getEncoded());
		}

		Log.addEntry("Sending public key X1 as DER: "
				+ HelperClass.toHexString(dad_Tag_84),
				LogType.INFORMATION, LogState.AUTHENTICATE,
				LogLevel.LOW);
		RAPDU rapdu = new RAPDU(dad_Tag_84, (byte) 0x90,
				(byte) 0x00, LogState.AUTHENTICATE);
		jcard.sendRAPDU(rapdu, LogState.AUTHENTICATE);

	}

	@Override
	protected void commandMutualAuthentication_send()
			throws PACERuntimeException,
			InvalidCAPDUException, InvalidRAPDUException,
			InvalidActionException, ConnectionException,
			IOException, SecureMessagingException {
		CAPDU capdu = (CAPDU) jcard
				.getLastReceivedData(LogState.AUTHENTICATE);

		authentikationTokenY = DynamicAuthenticationData
				.convertDERToBytes(0x85, capdu.getData());
		if (authentikationTokenY == null) {
			throw new PACERuntimeException(
					"Could not receive authentikation token",
					LogState.AUTHENTICATE);
		}

		Log.addEntry(
				"Recieved authentication token: "
						+ HelperClass
								.toHexString(authentikationTokenY),
				LogType.INFORMATION, LogState.AUTHENTICATE,
				LogLevel.LOW);

		byte[] dad_Tag_86 = DynamicAuthenticationData
				.convertBytesToDER(0x86,
						authentikationTokenX);

		Log.addEntry(
				"Sending authentication token as DER: "
						+ HelperClass
								.toHexString(dad_Tag_86),
				LogType.INFORMATION, LogState.AUTHENTICATE,
				LogLevel.LOW);
		RAPDU rapdu = new RAPDU(dad_Tag_86, (byte) 0x90,
				(byte) 0x00, LogState.AUTHENTICATE);
		jcard.sendRAPDU(rapdu, LogState.AUTHENTICATE);
	}
}