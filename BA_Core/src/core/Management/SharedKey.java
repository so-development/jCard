package core.Management;

/**
 * This class represents a shared key which can be used in authentication phase.
 * i.e. pin and can may be shared keys
 * 
 * @author Mark Forjahn
 * 
 */
public class SharedKey {
	private String key;

	public SharedKey(String key) {
		this.key = key;
	}

	public String getKeyAsString() {
		return key;
	}

	public byte[] getKeyAsByteArray() {
		return key.getBytes();
	}

}
