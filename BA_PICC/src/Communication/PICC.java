package Communication;

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
import core.ISO7816_4.RAPDU;
import core.ISO7816_4.SecureMessaging.SecureMessaging;
import core.Logging.Log;
import core.Logging.LogLevel;
import core.Logging.LogState;
import core.Logging.LogType;
import core.Management.ApplicationRegistry;
import core.Management.PACEProtocol_Settings;
import core.Management.Settings;

import Authentication.PICCPACE;
import Communication.Connection.PICCConnection;
import Management.PICCApplication;
import Management.PICCPACEProtocol_Settings;

import android.nfc.Tag;

/**
 * Chipcard procedure
 * 
 * @author Mark Forjahn
 * 
 */
public class PICC extends Procedure {

	private Tag tag;
	private String tech;
	private PICCApplication application;

	public PICC(Settings settings,
			ApplicationRegistry applicationRegistry,
			Tag tag, String tech) {
		super(settings, applicationRegistry,
				DeviceType.PICC);
		this.tag = tag;
		this.tech = tech;
	}

	@Override
	protected void initializeJCard()
			throws ConnectionException,
			InvalidCAPDUException, InvalidRAPDUException,
			InvalidActionException,
			SecureMessagingException {
		PICCConnection scc = new PICCConnection(tag, tech);
		scc.initialize();
		scc.connect();

		jcardManagement = new JCardManagement(scc,
				deviceType);
		jcardManagement.getJCard().sendRAPDU(
				new RAPDU((byte) 0x90, (byte) 0x00),
				LogState.INITIALIZE_JCARD);
	}

	@Override
	protected void initializeApplicationID()
			throws AIDNotFoundException,
			InvalidActionException, ConnectionException,
			InvalidRAPDUException, InvalidCAPDUException,
			InitializeApplicationIDException,
			SecureMessagingException {
		CAPDU capdu = (CAPDU) jcardManagement.getJCard()
				.getLastReceivedData(
						LogState.INITIALIZE_APPLICATION_ID);

		byte[] aid = capdu.getData();

		Application app = applicationRegistry
				.getApplication(aid,
						LogState.INITIALIZE_APPLICATION_ID);
		if (app instanceof PICCApplication) {
			application = (PICCApplication) app;
			application
					.setJCard(jcardManagement.getJCard());
			jcardManagement.getJCard().sendRAPDU(
					new RAPDU((byte) 0x90, (byte) 0x00),
					LogState.INITIALIZE_APPLICATION_ID);

		} else {
			throw new InitializeApplicationIDException(
					"Registered Application must be an PICCApplication!",
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
			auth = new PaceProcedure(
					new PICCPACE(
							jcardManagement.getJCard(),
							settings.getAuthenticationProtocol()
									.getKeyManagement(),
							((PICCPACEProtocol_Settings) settings
									.getAuthenticationProtocol())
									.getStandardizedDomainParameterID(),
							((PICCPACEProtocol_Settings) settings
									.getAuthenticationProtocol())
									.getAlgorithm()));
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
					"Secure messaging could not be instantiated with authentication protocol!",
					LogState.AUTHENTICATE);
		}
	}

	@Override
	protected void startApplication()
			throws ApplicationStartingException {
		application.startApplication();
	}

}
