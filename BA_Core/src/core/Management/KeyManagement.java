package core.Management;

import core.Exceptions.SecretNotSetException;
import core.Logging.LogState;

/**
 * This class contains possible shared secret which can be used at runtime
 * 
 * @author Mark Forjahn
 * 
 */

public class KeyManagement {
	private SharedKey can;
	private SharedKey pin;

	public SharedKey getCAN() throws SecretNotSetException {
		if (can == null) {
			throw new SecretNotSetException(
					"Cannot give CAN back",
					LogState.AUTHENTICATE);
		}
		return can;
	}

	public void setCAN(SharedKey can) {
		this.can = can;
	}

	public SharedKey getPIN() throws SecretNotSetException {
		if (pin == null) {
			throw new SecretNotSetException(
					"Cannot give PIN back",
					LogState.AUTHENTICATE);
		}
		return pin;
	}

	public void setPIN(SharedKey pin) {
		this.pin = pin;
	}

}
