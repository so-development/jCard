package core.Management;

/**
 * Information in this class are set before running the PACE-Protocol.
 * Information which are set in here will be used while the PACE Protocol runs.
 * 
 * @author Mark Forjahn
 * 
 */
public class PACEProtocol_Settings {
	private KeyManagement keyManagement;

	public PACEProtocol_Settings() {
		this.keyManagement = new KeyManagement();
		keyManagement.setPIN(new SharedKey(""));
		keyManagement.setCAN(new SharedKey(""));
	}

	public void setPIN(String pin) {
		SharedKey skPIN = new SharedKey(pin);
		keyManagement.setPIN(skPIN);

	}

	public void setCAN(String can) {
		SharedKey skCAN = new SharedKey(can);
		keyManagement.setCAN(skCAN);
	}

	public KeyManagement getKeyManagement() {
		return this.keyManagement;
	}

}
