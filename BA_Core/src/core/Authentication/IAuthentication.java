package core.Authentication;

import core.Exceptions.PACEFunctionsException;
import core.Exceptions.PACERuntimeException;
import core.ISO7816_4.SecureMessaging.SecureMessaging;

/**
 * Interface for all supported authentication protocols
 * 
 * @author Mark Forjahn
 * 
 */
public interface IAuthentication {

	SecureMessaging authenticate() throws PACERuntimeException,
			PACEFunctionsException;
}
