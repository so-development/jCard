package core.Communication;

import core.Communication.Connection.IConnection;
import core.Exceptions.SecureMessagingException;
import core.ISO7816_4.SecureMessaging.SecureMessaging;
import core.Logging.LogState;

/**
 * This class can add secure messaging to an existing connection. Since secure
 * messaging can be used after running PACE secure messaging needs to be added
 * at runtime.
 * 
 * @author Mark Forjahn
 * 
 */
public class JCardManagement {

	private JCard jcard; // Actual connection
	private IConnection connection; // "physical" connection
	private DeviceType deviceType; // actual device

	public JCardManagement(IConnection connection,
			DeviceType deviceType) {
		this.connection = connection;
		this.deviceType = deviceType;
		jcard = new JCard(connection, deviceType);
	}

	/**
	 * This method "adds" secure messaging to the existing connection
	 * 
	 * @param secureMessaging
	 * @throws SecureMessagingException
	 */
	public void setSecureMessaging(
			SecureMessaging secureMessaging, LogState state)
			throws SecureMessagingException {
		jcard = new JCard(connection, deviceType,
				secureMessaging,
				jcard.getLastReceivedData(state));

	}

	public JCard getJCard() {
		return jcard;
	}

}
