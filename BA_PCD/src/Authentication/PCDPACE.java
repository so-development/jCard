package Authentication;

import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.math.ec.ECCurve.Fp;

import core.Authentication.ASN1.DynamicAuthenticationData;
import core.Authentication.ASN1.MSESetAT;
import core.Authentication.ASN1.PACEInfo;
import core.Authentication.PACE.DPTypes;
import core.Authentication.PACE.PACE;
import core.Authentication.PACE.PACEFunctions;
import core.Authentication.PACE.PasswordTypes;
import core.Communication.JCard;
import core.Exceptions.ConnectionException;
import core.Exceptions.InvalidActionException;
import core.Exceptions.InvalidCAPDUException;
import core.Exceptions.InvalidRAPDUException;
import core.Exceptions.PACEFunctionsException;
import core.Exceptions.PACERuntimeException;
import core.Exceptions.SecretNotSetException;
import core.Exceptions.SecureMessagingException;
import core.ISO7816_4.CAPDU;
import core.ISO7816_4.RAPDU;
import core.ISO7816_4.Responses;
import core.Logging.Log;
import core.Logging.LogLevel;
import core.Logging.LogState;
import core.Logging.LogType;
import core.Management.KeyManagement;
import core.Support.HelperClass;

/**
 * This class contains all needed actions to perform PACE on PCD
 * 
 * @author Mark Forjahn
 * 
 */
public class PCDPACE extends PACE {

	public PCDPACE(JCard jcard,
			KeyManagement keyManagement, PasswordTypes type) {
		super(jcard, keyManagement);
		this.pwType = type;
	}

	@Override
	public void efCardAccess_message()
			throws PACERuntimeException {
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
		String pi = null;
		try {
			commandGetNonce_send();
			pi = this.pwType.equals(PasswordTypes.PIN) ? keyManagement
					.getPIN().getKeyAsString()
					: keyManagement.getCAN()
							.getKeyAsString();
		} catch (InvalidRAPDUException e) {
			throw new PACERuntimeException(e.getMessage(),
					LogState.AUTHENTICATE);
		} catch (InvalidCAPDUException e) {
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
		} catch (SecretNotSetException e) {
			throw new PACERuntimeException(
					"Could not read shared secret",
					LogState.AUTHENTICATE);
		} catch (SecureMessagingException e) {
			throw new PACERuntimeException(e.getMessage(),
					LogState.AUTHENTICATE);
		}

		byte[] kpi = PACEFunctions.kdf(
				PACEFunctions.f(pi, pwType), 3, algorithm);
		Log.addEntry(
				"Kpi derived: "
						+ HelperClass.toHexString(kpi),
				LogType.INFORMATION, LogState.AUTHENTICATE,
				LogLevel.LOW);

		this.nonce_s = PACEFunctions.d(kpi,
				this.nonce_encrypted_z, algorithm);
		Log.addEntry(
				"Nonce s decyrpted: "
						+ HelperClass.toHexString(nonce_s),
				LogType.INFORMATION, LogState.AUTHENTICATE,
				LogLevel.LOW);

	}

	@Override
	protected void efCardAccess_message_send()
			throws PACERuntimeException,
			InvalidCAPDUException, InvalidRAPDUException,
			InvalidActionException, ConnectionException,
			IOException, SecureMessagingException {
		// Read Binary -> 00 B0
		CAPDU capdu = new CAPDU((byte) 0x00, (byte) 0xB0,
				(byte) 0x00, (byte) 0x00);
		Log.addEntry(
				"Sending command: \"Read Binary\" - get EF.CardAccess file from chipcard",
				LogType.INFORMATION, LogState.AUTHENTICATE,
				LogLevel.LOW);

		jcard.sendCAPDU(capdu, LogState.AUTHENTICATE);

		RAPDU resp = (RAPDU) jcard
				.getLastReceivedData(LogState.AUTHENTICATE);
		// Check response
		if (!HelperClass.toHexString(resp.getSW()).equals(
				HelperClass.toHexString(Responses.SUCCESS))) {
			throw new PACERuntimeException(
					"PICC didn't answer with <<SUCCESS>> -- answer: "
							+ HelperClass.toHexString(resp
									.getBytes()),
					LogState.AUTHENTICATE);
		}

		PACEInfo paceInfo = new PACEInfo(resp.getData());

		analyse_efCardAccess(paceInfo);
	}

	private void analyse_efCardAccess(PACEInfo paceInfo)
			throws PACERuntimeException {

		// Here we could analyse the available oid's and chose one.
		// In this case we take the only one which is transmitted
		Log.addEntry(
				"Got PaceInfo - oid: "
						+ paceInfo.getProtocolOID()
						+ "; parameterId: "
						+ paceInfo.getParameterId(),
				LogType.INFORMATION, LogState.AUTHENTICATE,
				LogLevel.LOW);

		String chosenOID = paceInfo.getProtocolOID();
		DERObjectIdentifier oid = new DERObjectIdentifier(
				chosenOID);
		setConfiguration(oid, paceInfo.getParameterId());
	}

	@Override
	protected void commandMSESetAT_send()
			throws PACERuntimeException,
			InvalidCAPDUException, InvalidRAPDUException,
			InvalidActionException, ConnectionException,
			IOException, SecureMessagingException {

		Log.addEntry("Creating MSE:Set AT - oid: "
				+ getActualProtocolOID()
				+ "; shared secret type: " + pwType
				+ "; parameterId: " + dp.getId(),
				LogType.INFORMATION, LogState.AUTHENTICATE,
				LogLevel.LOW);

		MSESetAT msesetat = new MSESetAT(
				getActualProtocolOID(), dp.getId(),
				this.pwType);
		CAPDU capdu = new CAPDU((byte) 0x00, (byte) 0x22,
				(byte) 0xC1, (byte) 0xA4,
				msesetat.getDEREncoded(),
				LogState.AUTHENTICATE);

		jcard.sendCAPDU(capdu, LogState.AUTHENTICATE);
		RAPDU resp = (RAPDU) jcard
				.getLastReceivedData(LogState.AUTHENTICATE);
		// Check response
		if (!HelperClass.toHexString(resp.getSW()).equals(
				HelperClass.toHexString(Responses.SUCCESS))) {
			throw new PACERuntimeException(
					"PICC didn't answer with <<SUCCESS>> -- answer: "
							+ HelperClass.toHexString(resp
									.getBytes()),
					LogState.AUTHENTICATE);
		}
	}

	@Override
	protected void commandGetNonce_send()
			throws PACERuntimeException,
			InvalidCAPDUException, InvalidRAPDUException,
			InvalidActionException, ConnectionException,
			IOException, SecureMessagingException {

		// CLA: 10 -> Command Chaining
		// INS: 86 -> General Authenticate
		// P1/P2: 00 00 -> Keys and protocol implicitly known
		// Data: Tag:7C 

		byte[] data = new byte[] { 0x7C, 0x00 };
		CAPDU capdu = new CAPDU((byte) 0x10, (byte) 0x86,
				(byte) 0x00, (byte) 0x00, data,
				LogState.AUTHENTICATE);

		jcard.sendCAPDU(capdu, LogState.AUTHENTICATE);

		RAPDU resp = (RAPDU) jcard
				.getLastReceivedData(LogState.AUTHENTICATE);
		// Check response
		if (!HelperClass.toHexString(resp.getSW()).equals(
				HelperClass.toHexString(Responses.SUCCESS))) {
			throw new PACERuntimeException(
					"PICC didn't answer with <<SUCCESS>> -- answer: "
							+ HelperClass.toHexString(resp
									.getBytes()),
					LogState.AUTHENTICATE);
		}

		nonce_encrypted_z = DynamicAuthenticationData
				.convertDERToBytes(0x80, resp.getData());
		if (nonce_encrypted_z == null) {
			throw new PACERuntimeException(
					"Could not receive encrypted nonce z",
					LogState.AUTHENTICATE);
		}
		Log.addEntry(
				"Encrypted nonce z recieved: "
						+ HelperClass
								.toHexString(nonce_encrypted_z),
				LogType.INFORMATION, LogState.AUTHENTICATE,
				LogLevel.LOW);

	}

	@Override
	protected void commandMapNonce_send()
			throws PACERuntimeException,
			InvalidCAPDUException, InvalidRAPDUException,
			InvalidActionException, ConnectionException,
			IOException, SecureMessagingException {
		// Sende CAPDU

		// CLA: 10 -> Command Chaining
		// INS: 86 -> General Authenticate
		// P1/P2: 00 00 -> Keys and protocol implicitly known
		// Data: Tag:7C 

		byte[] dad_Tag_81 = null;
		if (this.dp.getType().equals(DPTypes.DH)) {
			dad_Tag_81 = DynamicAuthenticationData
					.convertBytesToDER(0x81,
							((DHPublicKeyParameters) X1)
									.getY().toByteArray());
		} else {
			dad_Tag_81 = DynamicAuthenticationData
					.convertBytesToDER(0x81,
							((ECPublicKeyParameters) X1)
									.getQ().getEncoded());
		}

		Log.addEntry("Sending public key X1 as DER: "
				+ HelperClass.toHexString(dad_Tag_81),
				LogType.INFORMATION, LogState.AUTHENTICATE,
				LogLevel.LOW);
		CAPDU capdu = new CAPDU((byte) 0x10, (byte) 0x86,
				(byte) 0x00, (byte) 0x00, dad_Tag_81,
				LogState.AUTHENTICATE);

		jcard.sendCAPDU(capdu, LogState.AUTHENTICATE);

		RAPDU resp = (RAPDU) jcard
				.getLastReceivedData(LogState.AUTHENTICATE);
		// Check response
		if (!HelperClass.toHexString(resp.getSW()).equals(
				HelperClass.toHexString(Responses.SUCCESS))) {
			throw new PACERuntimeException(
					"PICC didn't answer with <<SUCCESS>> -- answer: "
							+ HelperClass.toHexString(resp
									.getBytes()),
					LogState.AUTHENTICATE);
		}

		byte[] Y1Bytes = DynamicAuthenticationData
				.convertDERToBytes(0x82, resp.getData());
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
		}

	}

	@Override
	protected void commandPerformKeyAgreement_send()
			throws PACERuntimeException,
			InvalidCAPDUException, InvalidRAPDUException,
			InvalidActionException, ConnectionException,
			IOException, SecureMessagingException {
		// Sende CAPDU

		// CLA: 10 -> Command Chaining
		// INS: 86 -> General Authenticate
		// P1/P2: 00 00 -> Keys and protocol implicitly known
		// Data: Tag:7C 

		byte[] dad_Tag_83 = null;
		if (this.dp.getType().equals(DPTypes.DH)) {
			dad_Tag_83 = DynamicAuthenticationData
					.convertBytesToDER(0x83,
							((DHPublicKeyParameters) X2)
									.getY().toByteArray());
		} else {
			dad_Tag_83 = DynamicAuthenticationData
					.convertBytesToDER(0x83,
							((ECPublicKeyParameters) X2)
									.getQ().getEncoded());
		}

		Log.addEntry("Sending public key X2 as DER: "
				+ HelperClass.toHexString(dad_Tag_83),
				LogType.INFORMATION, LogState.AUTHENTICATE,
				LogLevel.LOW);
		CAPDU capdu = new CAPDU((byte) 0x10, (byte) 0x86,
				(byte) 0x00, (byte) 0x00, dad_Tag_83,
				LogState.AUTHENTICATE);

		jcard.sendCAPDU(capdu, LogState.AUTHENTICATE);

		RAPDU resp = (RAPDU) jcard
				.getLastReceivedData(LogState.AUTHENTICATE);
		// Check response
		if (!HelperClass.toHexString(resp.getSW()).equals(
				HelperClass.toHexString(Responses.SUCCESS))) {
			throw new PACERuntimeException(
					"PICC didn't answer with <<SUCCESS>> -- answer: "
							+ HelperClass.toHexString(resp
									.getBytes()),
					LogState.AUTHENTICATE);
		}

		byte[] Y2Bytes = DynamicAuthenticationData
				.convertDERToBytes(0x84, resp.getData());
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
		}

	}

	@Override
	protected void commandMutualAuthentication_send()
			throws PACERuntimeException,
			InvalidCAPDUException, InvalidRAPDUException,
			InvalidActionException, ConnectionException,
			IOException, SecureMessagingException {
		// Sende CAPDU

		// CLA: 00 -> No Command Chaining
		// INS: 86 -> General Authenticate
		// P1/P2: 00 00 -> Keys and protocol implicitly known
		// Data: Tag:7C 

		byte[] dad_Tag_85 = DynamicAuthenticationData
				.convertBytesToDER(0x85,
						authentikationTokenX);
		Log.addEntry(
				"Sending authentication token as DER: "
						+ HelperClass
								.toHexString(dad_Tag_85),
				LogType.INFORMATION, LogState.AUTHENTICATE,
				LogLevel.LOW);
		CAPDU capdu = new CAPDU((byte) 0x00, (byte) 0x86,
				(byte) 0x00, (byte) 0x00, dad_Tag_85,
				LogState.AUTHENTICATE);

		jcard.sendCAPDU(capdu, LogState.AUTHENTICATE);

		RAPDU resp = (RAPDU) jcard
				.getLastReceivedData(LogState.AUTHENTICATE);
		// Check response
		if (!HelperClass.toHexString(resp.getSW()).equals(
				HelperClass.toHexString(Responses.SUCCESS))) {
			throw new PACERuntimeException(
					"PICC didn't answer with <<SUCCESS>> -- answer: "
							+ HelperClass.toHexString(resp
									.getBytes()),
					LogState.AUTHENTICATE);
		}

		authentikationTokenY = DynamicAuthenticationData
				.convertDERToBytes(0x86, resp.getData());
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

	}

}
