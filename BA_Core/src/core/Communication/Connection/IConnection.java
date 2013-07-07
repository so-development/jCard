package core.Communication.Connection;

import core.Exceptions.ConnectionException;
import core.Exceptions.InvalidCAPDUException;
import core.Exceptions.InvalidRAPDUException;
import core.ISO7816_4.APDU;
import core.Logging.LogState;

/**
 * This interface provides different methods all connection types have to
 * implement
 * 
 * @author Mark Forjahn
 * 
 */
public interface IConnection {

	public void initialize() throws ConnectionException;

	public void connect() throws ConnectionException;

	public APDU send(APDU data, LogState state)
			throws ConnectionException,
			InvalidRAPDUException, InvalidCAPDUException;

	public void closeConnection();
}
