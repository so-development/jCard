package com.ba_picc;

import android.os.Bundle;
import android.preference.PreferenceActivity;

/**
 * Shows settings
 * 
 * @author Mark Forjahn
 * 
 */
public class SettingsActivity extends PreferenceActivity {

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		addPreferencesFromResource(R.xml.settings);

	}
}
