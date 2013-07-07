package com.ba_picc;

import core.Management.Management;
import Communication.PICC;
import android.nfc.Tag;
import android.os.AsyncTask;
import android.os.Looper;

/**
 * Background worker -> Screen does not freeze while authentication phase. Calls
 * back to MainScreen {@link MainScreen} at the end
 * 
 * @author Mark Forjahn
 * 
 */
public class Worker extends AsyncTask<Void, Integer, Void> {

	private PICC picc;
	private Management management;
	private String tech;
	private Tag tag;
	private MainScreen myActivity;
	private Exception exception;

	public Worker(MainScreen myActivity,
			Management management, Tag tag, String tech) {
		this.management = management;
		this.tech = tech;
		this.tag = tag;
		this.myActivity = myActivity;
	}

	protected Void doInBackground(Void... params) {
		try {
			Looper.prepare();
		} catch (Exception e) {
		}

		picc = new PICC(management.getSettings(),
				management.getApplicationRegistry(), tag,
				tech);
		exception = picc.start();
		return null;
	}

	@Override
	protected void onPostExecute(Void v) {
		myActivity.setProgrossDialogStopped();
		myActivity.callBack(exception);
	}

	@Override
	protected void onPreExecute() {
		myActivity.setProgrossDialogAktiv();
	}
}
