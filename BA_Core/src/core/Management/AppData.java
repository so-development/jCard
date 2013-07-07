package core.Management;

import java.util.HashMap;

/**
 * This class stores additional data for an application
 * 
 * @author Mark Forjahn
 * 
 */
public class AppData {
	private HashMap<String, String> appData = new HashMap<String, String>();

	public void addAppData(String key, String value) {
		appData.put(key, value);
	}

	public String getData(String key) {
		return appData.get(key);
	}

}
