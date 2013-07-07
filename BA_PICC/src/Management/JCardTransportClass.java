package Management;

import core.Communication.JCard;

/**
 * "Transports" a jCard object to the application
 * 
 * @author Mark Forjahn
 *
 */
public class JCardTransportClass {

	private static JCard jcard;

	public static JCard getJcard() {
		return jcard;
	}

	public static void setJcard(JCard jcard) {
		JCardTransportClass.jcard = jcard;
	}
}
