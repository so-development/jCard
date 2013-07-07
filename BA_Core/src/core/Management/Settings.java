package core.Management;



/**
 * This class contains settings for the runtime.
 * 
 * @author Mark Forjahn
 * 
 */
public class Settings {
	private PACEProtocol_Settings authProt = null;

	public void setAuthenticationProtocol(
			PACEProtocol_Settings authProt) {
		this.authProt = authProt;
	}

	public PACEProtocol_Settings getAuthenticationProtocol() {
		return this.authProt;
	}
}
