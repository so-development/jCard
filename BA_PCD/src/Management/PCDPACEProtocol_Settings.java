package Management;

import core.Authentication.PACE.PasswordTypes;
import core.Management.PACEProtocol_Settings;

/**
 * Contains all needed information to PACE procedure at runtime
 * 
 * @author Mark Forjahn
 * 
 */
public class PCDPACEProtocol_Settings extends
		PACEProtocol_Settings {

	private PasswordTypes type; // On PCD side, at runtime the password type can
								// be chosen

	public PasswordTypes getPasswordType() {
		return type;
	}

	public void setPasswordType(PasswordTypes type) {
		this.type = type;
	}

}
