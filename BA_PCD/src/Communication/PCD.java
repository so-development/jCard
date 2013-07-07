package Communication;

import Authentication.PCDPACE;
import Communication.Connection.PCDConnection;
import Management.PCDApplication;
import Management.PCDPACEProtocol_Settings;
import core.Application.Application;
import core.Authentication.IAuthentication;
import core.Authentication.PACE.PaceProcedure;
import core.Communication.DeviceType;
import core.Communication.JCardManagement;
import core.Communication.Procedure;
import core.Exceptions.AIDNotFoundException;
import core.Exceptions.ApplicationStartingException;
import core.Exceptions.AuthenticateException;
import core.Exceptions.ConnectionException;
import core.Exceptions.InitializeApplicationIDException;
import core.Exceptions.InvalidActionException;
import core.Exceptions.InvalidCAPDUException;
import core.Exceptions.InvalidRAPDUException;
import core.Exceptions.PACEFunctionsException;
import core.Exceptions.PACERuntimeException;
import core.Exceptions.SecureMessagingException;
import core.ISO7816_4.CAPDU;
import core.ISO7816_4.Commands;
import core.ISO7816_4.Responses;
import core.ISO7816_4.SecureMessaging.SecureMessaging;
import core.Logging.Log;
import core.Logging.LogLevel;
import core.Logging.LogState;
import core.Logging.LogType;
import core.Management.ApplicationRegistry;
import core.Management.PACEProtocol_Settings;
import core.Management.Settings;
import core.Support.HelperClass;

/**
 * Represents whole procedure on PCD
 * 
 * @author Mark Forjahn
 * 
 */
public class PCD extends Procedure {

	private PCDApplication application;
	private byte[] aid;

	public PCD(Settings settings,
			ApplicationRegistry applicationRegistry,
			byte[] aid) {
		super(settings, applicationRegistry, DeviceType.PCD);
		this.aid = aid;
	}

	@Override
	protected void initializeJCard()
			throws ConnectionException {
		PCDConnection pcdc = new PCDConnection();
		pcdc.initialize();
		pcdc.connect();
		jcardManagement = new JCardManagement(pcdc,
				this.deviceType);
	}

	@Override
	protected void initializeApplicationID()
			throws InvalidCAPDUException,
			InvalidActionException, ConnectionException,
			InvalidRAPDUException, AIDNotFoundException,
			InitializeApplicationIDException,
			SecureMessagingException {
		// send this.aid
		CAPDU capdu = Commands.createAIDCommand(aid);
		jcardManagement.getJCard().sendCAPDU(capdu,
				LogState.INITIALIZE_APPLICATION_ID);

		if (!HelperClass
				.toHexString(
						jcardManagement
								.getJCard()
								.getLastReceivedData(
										LogState.INITIALIZE_APPLICATION_ID)
								.getBytes())
				.equals(HelperClass
						.toHexString(Responses.SUCCESS))) {
			throw new InitializeApplicationIDException(
					"PICC didn't answer with <<SUCCESS>> -- answer: "
							+ HelperClass.toHexString(jcardManagement
									.getJCard()
									.getLastReceivedData(
											LogState.INITIALIZE_APPLICATION_ID)
									.getBytes()),
					LogState.INITIALIZE_APPLICATION_ID);
		}

		Application app = applicationRegistry
				.getApplication(aid,
						LogState.INITIALIZE_APPLICATION_ID);
		if (app instanceof PCDApplication) {
			application = (PCDApplication) app;
			application
					.setJCard(jcardManagement.getJCard());
		} else {
			throw new InitializeApplicationIDException(
					"Registered Application must be an PCDApplication!",
					LogState.INITIALIZE_APPLICATION_ID);
		}
	}

	@Override
	protected void authenticate()
			throws AuthenticateException {
		IAuthentication auth = null;
		if (settings.getAuthenticationProtocol() == null) {
			throw new AuthenticateException(
					"No authentication protocol selected",
					LogState.AUTHENTICATE);
		}
		if (settings.getAuthenticationProtocol() instanceof PACEProtocol_Settings) {
			auth = new PaceProcedure(new PCDPACE(
					jcardManagement.getJCard(), settings
							.getAuthenticationProtocol()
							.getKeyManagement(),
					((PCDPACEProtocol_Settings) settings
							.getAuthenticationProtocol())
							.getPasswordType()));
		} else {
			throw new AuthenticateException(
					"Selected authentication protocol not available",
					LogState.AUTHENTICATE);
		}
		SecureMessaging secureMessaging = null;
		try {
			secureMessaging = auth.authenticate();
		} catch (PACERuntimeException e) {
			throw new AuthenticateException(e.getMessage(),
					LogState.AUTHENTICATE);
		} catch (PACEFunctionsException e) {
			throw new AuthenticateException(e.getMessage(),
					LogState.AUTHENTICATE);
		}

		if (secureMessaging != null) {
			Log.addEntry("Enable secure messaging ...",
					LogType.INFORMATION,
					LogState.AUTHENTICATE, LogLevel.HIGH);
			try {
				jcardManagement.setSecureMessaging(
						secureMessaging,
						LogState.AUTHENTICATE);
			} catch (SecureMessagingException e) {
				throw new AuthenticateException(
						"Secure messaging could not be created",
						LogState.AUTHENTICATE);
			}
			Log.addEntry("Secure messaging enabled!",
					LogType.INFORMATION,
					LogState.AUTHENTICATE, LogLevel.HIGH);
		} else {
			throw new AuthenticateException(
					"Secure messaging could not be created with authentication protocol!",
					LogState.AUTHENTICATE);
		}
	}

	@Override
	protected void startApplication()
			throws ApplicationStartingException {
		application.startApplication();
	}

}
