package core.Application;

import core.Communication.JCard;
import core.Exceptions.ApplicationStartingException;
import core.Management.AppData;

/**
 * This class is the abstract class for all applications that needs to be
 * created. (Application(s) for PICCs and PCDs are needed)
 * 
 * @author Mark Forjahn
 * 
 */
public abstract class Application {

	protected String name; // name of the application
	protected byte[] aid; // aid of the application
	protected JCard jcard; // application contains a jCard object to be able to
							// send and receive data
	protected AppData appData;

	public Application(String name, byte[] aid) {
		this.aid = aid;
		this.name = name;
	}

	public String getName() {
		return this.name;
	}

	public byte[] getAID() {
		return aid;
	}

	public JCard getJCard() {
		return this.jcard;
	}
	public void addAppData(AppData appData){
		this.appData = appData;
	}

	public AppData getAppData() {
		return this.appData;
	}

	public void setJCard(JCard jcard) {
		this.jcard = jcard;
	}

	/**
	 * Application starting is different for a PICC application and PCD
	 * application
	 * 
	 * @throws ApplicationStartingException
	 *             Thrown in case of starting errors
	 */
	public abstract void startApplication()
			throws ApplicationStartingException;

}
