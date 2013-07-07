package core.Application;

import core.Communication.JCard;
import core.Management.AppData;

/**
 * Interface which must be used for a specific application of a PCD.
 * 
 * @author Mark Forjahn
 * 
 */
public interface IPCDApplication {
	/**
	 * This method is called to start the created application
	 * 
	 * @param jcard
	 *            contains established connection
	 *        
 	* @param appData
	 *            contains additional data for the app
	 */
	public void start(JCard jcard, AppData appData);

}
