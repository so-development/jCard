package com.ba_pcd;

import java.util.Scanner;

import Communication.PCD;
import Management.PCDApplication;
import Management.PCDPACEProtocol_Settings;
import core.Application.Application;
import core.Authentication.PACE.PasswordTypes;
import core.Exceptions.KeyManagementException;
import core.Logging.Log;
import core.Management.AppData;
import core.Management.Management;
import core.Management.PACEProtocol_Settings;

/**
 * Main class for PCD
 * 
 * @author Mark Forjahn
 * 
 */
public class Main {

	private static Management management;
	private static PACEProtocol_Settings authProt;
	private static PCD pcd;

	private static byte[] sepkiAID = { (byte) 0xA0, 0x00,
			0x00, 0x00, 0x01, 0x01 };

	public static void main(String[] args) {

		management = new Management();
		authProt = new PCDPACEProtocol_Settings();

		management.setAuthenticationProtocol(authProt);

		try {
			initializeApplications();
		} catch (KeyManagementException e) {
		}

		menu();
	}

	private static void run(byte[] aid) {
		pcd = new PCD(management.getSettings(),
				management.getApplicationRegistry(), aid);
		Exception success = pcd.start();

	}

	private static void initializeApplications()
			throws KeyManagementException {
		PCDApplication pcdApp = new PCDApplication(
				"PKI Emulator", sepkiAID,
				"com.ba_pcd.SEPKIClient");
		management.addApplication(pcdApp);
	}

	private static void choseApp() {
		boolean insertOK = false;
		while (!insertOK) {
			System.out
					.println("Please chose the application you want to use:");
			Object[] obj = management
					.getApplicationRegistry()
					.getAllApplications();

			for (int i = 0; i < obj.length; i++) {
				System.out.println(i + 1 + ". "
						+ ((Application) obj[i]).getName());
			}

			int app = 0;
			try {
				Scanner insert = new Scanner(System.in);
				app = insert.nextInt();
			} catch (Exception e) {
				insertOK = false;
			}

			if (app > 0 && app <= obj.length) {
				insertOK = true;
				chosePasswordType();
				AppData appData = addAppData();
				try {
					((Application) obj[app - 1])
							.addAppData(appData);
					run(((Application) obj[app - 1])
							.getAID());
				} catch (Exception e) {
					e.printStackTrace();
				}
			} else {
				insertOK = false;
			}
		}

	}

	private static AppData addAppData() {

		boolean insertOK = false;
		boolean finished = false;
		int argument = 0;
		AppData appData = new AppData();

		while (!finished) {
			while (!insertOK) {
				System.out
						.println("Do you want to add data to your application?");
				System.out.println("(1) Yes");
				System.out.println("(2) No");
				try {
					Scanner insert = new Scanner(System.in);
					argument = insert.nextInt();
					if (argument > 0 && argument < 3) {
						insertOK = true;
					} else {
						insertOK = false;
					}
				} catch (Exception e) {
					insertOK = false;
				}
			}
			insertOK = false;
			switch (argument) {
			case 1:
				System.out
						.println("Please enter the identifier:");
				String key = "";
				Scanner insert = new Scanner(System.in);
				key = insert.nextLine();

				System.out
						.println("Please enter the value:");
				String value = "";
				value = insert.nextLine();

				appData.addAppData(key, value);
				System.out.println("Added!");
				break;
			default:
				finished = true;
				break;
			}
		}
		return appData;
	}

	private static void chosePasswordType() {

		boolean insertOK = false;
		int argument = 0;

		while (!insertOK) {
			System.out
					.println("Which type of shared secret shall be used?");
			System.out.println("(1) PIN");
			System.out.println("(2) CAN");

			try {
				Scanner insert = new Scanner(System.in);
				argument = insert.nextInt();
				if (argument > 0 && argument < 3) {
					insertOK = true;
				} else {
					insertOK = false;
				}
			} catch (Exception e) {
				insertOK = false;
			}

			if (!insertOK) {
				System.out.println("Wrong number!");
			}
		}
		switch (argument) {
		case 1:
			System.out.println("Please enter new PIN:");
			String newPin = "";
			Scanner insert = new Scanner(System.in);
			newPin = insert.nextLine();
			authProt.setPIN(newPin);
			((PCDPACEProtocol_Settings) authProt)
					.setPasswordType(PasswordTypes.PIN);
			System.out.println("New PIN set: " + newPin);
			break;
		case 2:
			System.out.println("Please enter new CAN:");
			String newCan = "";
			Scanner insert1 = new Scanner(System.in);
			newCan = insert1.nextLine();
			authProt.setCAN(newCan);
			((PCDPACEProtocol_Settings) authProt)
					.setPasswordType(PasswordTypes.CAN);
			System.out.println("New CAN set: " + newCan);
			break;
		default:
			System.exit(0);
			break;
		}

	}

	private static void menu() {
		while (true) {
			Log.reset();
			boolean insertOK = false;
			int argument = 0;
			while (!insertOK) {
				System.out
						.println("What do you want to do?");
				System.out
						.println("(1) Start new application");
				System.out.println("(2) Exit");

				try {
					Scanner insert = new Scanner(System.in);
					argument = insert.nextInt();
					if (argument > 0 && argument < 3) {
						insertOK = true;
					} else {
						insertOK = false;
					}
				} catch (Exception e) {
					insertOK = false;
				}

				if (!insertOK) {
					System.out.println("Wrong number!");
				}
			}

			switch (argument) {
			case 1:
				choseApp();
				break;
			default:
				System.exit(0);
				break;
			}
		}
	}

}
