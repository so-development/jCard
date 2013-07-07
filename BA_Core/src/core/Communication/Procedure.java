package core.Communication;

import core.Authentication.IAuthentication;
import core.Exceptions.AIDNotFoundException;
import core.Exceptions.ApplicationStartingException;
import core.Exceptions.AuthenticateException;
import core.Exceptions.ConnectionException;
import core.Exceptions.InitializeApplicationIDException;
import core.Exceptions.InvalidActionException;
import core.Exceptions.InvalidCAPDUException;
import core.Exceptions.InvalidRAPDUException;
import core.Exceptions.OtherException;
import core.Exceptions.SecureMessagingException;
import core.Logging.Log;
import core.Logging.LogLevel;
import core.Logging.LogState;
import core.Logging.LogType;
import core.Management.ApplicationRegistry;
import core.Management.Settings;
import core.Support.StopWatch;

/**
 * This class handles the initializing and management of the API
 * 
 * @author Mark Forjahn
 * 
 */
public abstract class Procedure {
	protected Settings settings; // Settings from outside (i.e. authentication
									// information)
	protected DeviceType deviceType; // Current device
	protected JCardManagement jcardManagement; // API-Connection to send and
												// receive data
	protected ApplicationRegistry applicationRegistry; // All available
														// application that can
														// be run
	protected IAuthentication authentication; // Authenticates connection

	public Procedure(Settings settings,
			ApplicationRegistry applicationRegistry,
			DeviceType deviceType) {
		this.settings = settings;
		this.applicationRegistry = applicationRegistry;
		this.deviceType = deviceType;

	}

	/**
	 * Needs to be implemented on both sides - Physical initializing PCD can use
	 * Smartcardio; PICC needs to use special tag wrapper
	 * 
	 * @throws ConnectionException
	 * @throws InvalidCAPDUException
	 * @throws InvalidRAPDUException
	 * @throws InvalidActionException
	 */
	protected abstract void initializeJCard()
			throws ConnectionException,
			InvalidCAPDUException, InvalidRAPDUException,
			InvalidActionException,
			SecureMessagingException;

	/**
	 * Starts the whole procedure
	 * 
	 * @return Exception -> null if everything was OK
	 */
	public Exception start() {
		Exception returnException = null;
		try {
			Log.addEntry("Initialize JCard ...",
					LogType.INFORMATION,
					LogState.INITIALIZE_JCARD,
					LogLevel.HIGH);
			initializeJCard();
			Log.addEntry("Authenticate ...",
					LogType.INFORMATION,
					LogState.AUTHENTICATE, LogLevel.HIGH);
			StopWatch watch = new StopWatch(); // Time counter for
												// authentication phase
			watch.start();
			authenticate();
			int milliseconds = watch.getMilliSeconds();
			int seconds = Math.round((float) ((float) watch
					.getMilliSeconds() / (float) 1000));
			Log.addEntry("Authentication finished in "
					+ seconds + "s - (" + milliseconds
					+ "ms)", LogType.INFORMATION,
					LogState.AUTHENTICATE, LogLevel.HIGH);
			Log.addEntry("Initialize Application ID ...",
					LogType.INFORMATION,
					LogState.INITIALIZE_APPLICATION_ID,
					LogLevel.HIGH);
			initializeApplicationID();
			Log.addEntry("Starting Application ...",
					LogType.INFORMATION,
					LogState.APPLICATION_STARTING,
					LogLevel.HIGH);
			startApplication();
			Log.addEntry(
					"Application starting procedure done!",
					LogType.INFORMATION,
					LogState.APPLICATION_STARTING,
					LogLevel.HIGH);
		} catch (InvalidActionException e) {
			returnException = e;
			jcardManagement.getJCard().closeConnection();
		} catch (InvalidCAPDUException e) {
			returnException = e;
			jcardManagement.getJCard().closeConnection();
		} catch (ConnectionException e) {
			returnException = e;
			jcardManagement.getJCard().closeConnection();
		} catch (InvalidRAPDUException e) {
			returnException = e;
			jcardManagement.getJCard().closeConnection();
		} catch (AIDNotFoundException e) {
			returnException = e;
			jcardManagement.getJCard().closeConnection();
		} catch (ApplicationStartingException e) {
			returnException = e;
			jcardManagement.getJCard().closeConnection();
		} catch (InitializeApplicationIDException e) {
			returnException = e;
			jcardManagement.getJCard().closeConnection();
		} catch (AuthenticateException e) {
			returnException = e;
			jcardManagement.getJCard().closeConnection();
		} catch (SecureMessagingException e) {
			returnException = e;
			jcardManagement.getJCard().closeConnection();
		} catch (Exception e) {
			returnException = new OtherException(
					e.toString(), LogState.UNKNOWN);
			jcardManagement.getJCard().closeConnection();
		}

		return returnException;

	}

	/**
	 * Authentication phase
	 * 
	 * @throws AuthenticateException
	 */
	protected abstract void authenticate()
			throws AuthenticateException;

	/**
	 * Initializing of application id phase
	 * 
	 * @throws InvalidCAPDUException
	 * @throws InvalidActionException
	 * @throws ConnectionException
	 * @throws InvalidRAPDUException
	 * @throws AIDNotFoundException
	 * @throws InitializeApplicationIDException
	 */
	protected abstract void initializeApplicationID()
			throws InvalidCAPDUException,
			InvalidActionException, ConnectionException,
			InvalidRAPDUException, AIDNotFoundException,
			InitializeApplicationIDException,
			SecureMessagingException;

	/**
	 * Application starting phase
	 * 
	 * @throws ApplicationStartingException
	 */
	protected abstract void startApplication()
			throws ApplicationStartingException;

}
