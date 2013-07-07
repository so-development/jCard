package core.Authentication.PACE;

import core.Authentication.IAuthentication;
import core.Exceptions.PACEFunctionsException;
import core.Exceptions.PACERuntimeException;
import core.ISO7816_4.SecureMessaging.SecureMessaging;
import core.Logging.Log;
import core.Logging.LogLevel;
import core.Logging.LogState;
import core.Logging.LogType;

/**
 * This class handles the order in which the PACE-methods have to be called and
 * finally gives a SecureMessaging object back.
 * 
 * @author Mark Forjahn
 * 
 */
public class PaceProcedure implements IAuthentication {

	private PACE pace;

	public PaceProcedure(PACE pace) {
		this.pace = pace;
	}

	@Override
	public SecureMessaging authenticate() throws PACERuntimeException,
			PACEFunctionsException {
		Log.addEntry("PACE authentication selected", LogType.INFORMATION,
				LogState.AUTHENTICATE, LogLevel.HIGH);
		Log.addEntry("Configure EF.CardAccess information ...",
				LogType.INFORMATION, LogState.AUTHENTICATE, LogLevel.HIGH);
		pace.efCardAccess_message();
		Log.addEntry("Command \"MSE:Set AT\" now running ...",
				LogType.INFORMATION, LogState.AUTHENTICATE, LogLevel.HIGH);
		pace.commandMSESetAT();
		Log.addEntry("Command \"Get Nonce\" now running ...",
				LogType.INFORMATION, LogState.AUTHENTICATE, LogLevel.HIGH);
		pace.commandGetNonce();
		Log.addEntry("Command \"Map Nonce\" now running ...",
				LogType.INFORMATION, LogState.AUTHENTICATE, LogLevel.HIGH);
		pace.commandMapNonce();
		Log.addEntry("Command \"Perform Key Agreement\" now running ...",
				LogType.INFORMATION, LogState.AUTHENTICATE, LogLevel.HIGH);
		pace.commandPerformKeyAgreement();
		Log.addEntry("Generating shared secret 'K' ...", LogType.INFORMATION,
				LogState.AUTHENTICATE, LogLevel.HIGH);
		pace.generateSharedSecretK();
		Log.addEntry("Command \"Mutual Authentication\" now running ...",
				LogType.INFORMATION, LogState.AUTHENTICATE, LogLevel.HIGH);
		pace.commandMutualAuthentication();
		Log.addEntry("Checking received authentication token ...",
				LogType.INFORMATION, LogState.AUTHENTICATE, LogLevel.HIGH);
		pace.checkAuthenticationToken();
		Log.addEntry("PACE authentication finished successfully!",
				LogType.INFORMATION, LogState.AUTHENTICATE, LogLevel.HIGH);

		return initializeSecureMessaging();
	}

	private SecureMessaging initializeSecureMessaging() {
		return new SecureMessaging(pace.getK_ENC(), pace.getK_MAC(),
				pace.getAlgorithm());
	}

}
