package com.ba_picc;

import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.List;

import Management.PICCApplication;
import Management.PICCPACEProtocol_Settings;
import android.annotation.SuppressLint;
import android.app.ActionBar;
import android.app.Activity;
import android.app.AlertDialog;
import android.app.PendingIntent;
import android.app.ProgressDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.os.Build;
import android.os.Bundle;
import android.os.PowerManager;
import android.os.PowerManager.WakeLock;
import android.preference.PreferenceManager;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.ViewGroup.LayoutParams;
import android.view.Window;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;
import core.Authentication.PACE.Algorithms;
import core.Crypto.CryptFunctions;
import core.Exceptions.ApplicationStartingException;
import core.Logging.Log;
import core.Logging.LogType;
import core.Management.Management;
import core.Management.PACEProtocol_Settings;

public class MainScreen extends Activity {

	private Management management;
	private PACEProtocol_Settings authProt;

	private final String TECH_ISO_PCDA = "android.nfc.tech.IsoPcdA";

	private NfcAdapter adapter;
	private PendingIntent pendingIntent;
	private IntentFilter[] filters;
	private String[][] techLists;

	private PowerManager powerManager;
	private WakeLock wakeLock;

	ProgressDialog progressDialog;

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		requestWindowFeature(Window.FEATURE_INDETERMINATE_PROGRESS);

		setContentView(R.layout.activity_main_screen);

		powerManager = (PowerManager) getSystemService(Context.POWER_SERVICE);

		if (android.os.Build.VERSION.SDK_INT >= 11) {
			configActionBar();
		}

		initialize();
		initializeNFC();
		settingsSet();

		((Button) findViewById(R.id.b_enter_pin))
				.setOnClickListener(new OnClickListener() {

					@Override
					public void onClick(View v) {
						String pin = ((EditText) findViewById(R.id.et_pin))
								.getText().toString();
						authProt.setPIN(pin == null ? ""
								: pin);
						Toast.makeText(MainScreen.this,
								R.string.set_pin_success,
								Toast.LENGTH_SHORT).show();
					}
				});

	}

	public void initializeApplications() {
		byte[] sepkiAID = { (byte) 0xA0, 0x00, 0x00, 0x00,
				0x01, 0x01 };
		PICCApplication piccApp = new PICCApplication(
				"PKI Applet Emulator", sepkiAID, this,
				"com.ba_picc.sepki.PKIActivity");
		management.addApplication(piccApp);
	}

	public void initialize() {
		management = new Management();
		authProt = new PICCPACEProtocol_Settings();
		newCAN();
		getSettings();
		management.setAuthenticationProtocol(authProt);

		initializeApplications();
	}

	@SuppressLint("NewApi")
	public void configActionBar() {
		ActionBar actionBar = getActionBar();
		if (android.os.Build.VERSION.SDK_INT >= 14) {
			actionBar.setHomeButtonEnabled(false);
		}
	}

	public void initializeNFC() {

		adapter = NfcAdapter.getDefaultAdapter(this);
		adapter.setNdefPushMessage(null, this);
		if (Build.VERSION.SDK_INT > Build.VERSION_CODES.JELLY_BEAN) {
			adapter.setBeamPushUris(null, this);
		}

		pendingIntent = PendingIntent
				.getActivity(
						this,
						0,
						new Intent(this, getClass())
								.addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
						0);
		filters = new IntentFilter[] { new IntentFilter(
				NfcAdapter.ACTION_TECH_DISCOVERED) };
		techLists = new String[][] { { TECH_ISO_PCDA } };

		Intent intent = getIntent();
		handleTag(intent);
	}

	private void handleTag(Intent intent) {
		String action = intent.getAction();

		if (NfcAdapter.ACTION_TECH_DISCOVERED
				.equals(action)) {
			if (settingsSet()) {
				Tag tag = null;
				if (intent.getExtras() != null) {
					tag = (Tag) intent.getExtras().get(
							NfcAdapter.EXTRA_TAG);
				}
				if (tag == null) {
					return;
				}
				List<String> techList = Arrays.asList(tag
						.getTechList());

				if (!techList.contains(TECH_ISO_PCDA)) {
					return;
				}
				Worker worker = new Worker(this,
						management, tag, TECH_ISO_PCDA);
				worker.execute();
			}
		} else {
		}
	}

	public boolean settingsSet() {
		if (management != null) {
			if (management.getSettings() != null) {
				if (management.getSettings()
						.getAuthenticationProtocol() != null) {
					if (management.getSettings()
							.getAuthenticationProtocol() instanceof PICCPACEProtocol_Settings) {
						if (((PICCPACEProtocol_Settings) management
								.getSettings()
								.getAuthenticationProtocol())
								.getAlgorithm() == null
								|| ((PICCPACEProtocol_Settings) management
										.getSettings()
										.getAuthenticationProtocol())
										.getStandardizedDomainParameterID() == -1) {
							setSettingFirstDialog();
							return false;
						} else {
							return true;
						}
					}

				}
			}
		}
		return false;

	}

	public void setSettingFirstDialog() {
		AlertDialog.Builder builder = new AlertDialog.Builder(
				this);
		builder.setTitle(getResources().getString(
				R.string.information));
		builder.setMessage(
				getResources().getString(
						R.string.chose_dp_and_alg_first))
				.setNeutralButton(
						"OK",
						new DialogInterface.OnClickListener() {
							public void onClick(
									DialogInterface dialog,
									int id) {
							}
						});
		builder.create().show();
	}

	public void callBack(Exception exception) {
		if (exception != null) {
			Toast.makeText(MainScreen.this,
					R.string.running_error,
					Toast.LENGTH_LONG).show();
		}
		newCAN();
	}

	public void newCAN() {
		int newCan;
		try {
			newCan = CryptFunctions.createNewCAN();
			authProt.setCAN(String.valueOf(newCan));
			((TextView) findViewById(R.id.tv_config_can))
					.setText("" + newCan);
		} catch (NoSuchAlgorithmException e) {
		}
	}

	public void setProgrossDialogAktiv() {
		progressDialog = new ProgressDialog(MainScreen.this);
		synchronized (progressDialog) {
			progressDialog.setCancelable(false);
			progressDialog
					.setMessage(getResources()
							.getText(
									R.string.prepare_secure_connection));
			progressDialog
					.setProgressStyle(ProgressDialog.STYLE_SPINNER);
			progressDialog.setProgress(0);
			progressDialog.show();
		}
	}

	/**
	 * Stoppt den ProgressDialog
	 */
	public void setProgrossDialogStopped() {
		synchronized (progressDialog) {
			progressDialog.cancel();
		}
	}

	@Override
	public void onResume() {
		super.onResume();
		wakeLock = powerManager.newWakeLock(
				PowerManager.FULL_WAKE_LOCK,
				getString(R.string.app_name));
		wakeLock.acquire();

		if (adapter != null) {
			adapter.enableForegroundDispatch(this,
					pendingIntent, filters, techLists);
		}

	}

	@Override
	public void onPause() {
		super.onPause();
		if (adapter != null) {
			adapter.disableForegroundDispatch(this);
		}

		if (wakeLock != null) {
			wakeLock.release();
		}

	}

	@Override
	public void onDestroy() {
		super.onDestroy();
	}

	@Override
	public void onBackPressed() {
		finish();
	}

	@Override
	public void onNewIntent(Intent intent) {
		Log.reset();
		handleTag(intent);
	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		menu.add(1, 1, 1,
				getResources().getText(R.string.settings));
		menu.add(
				1,
				2,
				2,
				getResources().getText(
						R.string.config_applications));
		menu.add(1, 3, 3,
				getResources().getText(R.string.log));
		return true;
	}

	@Override
	public boolean onOptionsItemSelected(MenuItem item) {
		switch (item.getItemId()) {
		case 1:
			Intent i = new Intent(this,
					SettingsActivity.class);
			startActivityForResult(i, 10);
			break;
		case 2:
			showApplications();
			break;
		case 3:
			if (Log.getEntries(LogType.INFORMATION).size() > 0) {
				Intent intent = new Intent(
						getApplicationContext(),
						LogActivity.class);
				intent.putExtra("logEntries",
						Log.getEntries(LogType.INFORMATION));
				startActivity(intent);
			} else {
				Toast.makeText(MainScreen.this,
						R.string.no_log_entries_availabe,
						Toast.LENGTH_SHORT).show();
			}
			break;
		case 4:
			break;
		}
		return false;
	}

	public void showApplications() {
		LinearLayout apps = new LinearLayout(
				MainScreen.this);
		apps.setPadding(10, 5, 10, 5);

		ScrollView beschreibungsScrollView = new ScrollView(
				MainScreen.this);
		beschreibungsScrollView
				.setLayoutParams(new LayoutParams(
						LayoutParams.MATCH_PARENT,
						LayoutParams.WRAP_CONTENT));

		AlertDialog.Builder builder = new AlertDialog.Builder(
				MainScreen.this);
		builder.setView(beschreibungsScrollView);
		builder.setTitle(getResources().getString(
				R.string.config_applications));
		final AlertDialog alert = builder.create();

		final Object[] applications = management
				.getApplicationRegistry()
				.getAllApplications();
		for (int i = 0; i < applications.length; i++) {
			Button bApp = new Button(MainScreen.this);
			bApp.setLayoutParams(new LayoutParams(
					LayoutParams.MATCH_PARENT,
					LayoutParams.WRAP_CONTENT));
			final PICCApplication piccapp = (PICCApplication) applications[i];

			bApp.setText(piccapp.getName());
			bApp.setOnClickListener(new OnClickListener() {
				@Override
				public void onClick(View v) {
					try {
						piccapp.setJCard(null);
						piccapp.startApplication();
						alert.dismiss();
					} catch (ApplicationStartingException e) {
						Toast.makeText(
								MainScreen.this,
								R.string.start_application_error_config_mode,
								Toast.LENGTH_LONG).show();
					}
				}
			});
			apps.addView(bApp);
		}

		beschreibungsScrollView.addView(apps);

		alert.setCancelable(true);
		alert.setCanceledOnTouchOutside(true);
		alert.show();
	}

	@Override
	protected void onActivityResult(int requestCode,
			int resultCode, Intent data) {
		super.onActivityResult(requestCode, resultCode,
				data);

		switch (requestCode) {
		case 10:
			getSettings();
			break;
		}
	}

	public void getSettings() {
		SharedPreferences sharedPrefs = PreferenceManager
				.getDefaultSharedPreferences(MainScreen.this);

		if (authProt != null
				&& authProt instanceof PICCPACEProtocol_Settings) {
			int id = -1;
			id = Integer
					.valueOf(sharedPrefs
							.getString(
									"pref_key_domain_parameter_list",
									"-1"));

			int algorithm = -1;
			algorithm = Integer
					.valueOf(sharedPrefs.getString(
							"pref_key_algorithms", "-1"));

			if (algorithm == 112) {
				((TextView) findViewById(R.id.tv_config_algorithm))
						.setText(getResources()
								.getString(
										R.string.actual_pace_config_algorithm)
								+ " 3DES (112 Bit) CBC/CBC");
				((PICCPACEProtocol_Settings) authProt)
						.setAlgorithm(Algorithms._3DES_112);
			} else if (algorithm == 128) {
				((TextView) findViewById(R.id.tv_config_algorithm))
						.setText(getResources()
								.getString(
										R.string.actual_pace_config_algorithm)
								+ " AES (128 Bit) CBC/CMAC");
				((PICCPACEProtocol_Settings) authProt)
						.setAlgorithm(Algorithms._AES_128);
			} else if (algorithm == 192) {
				((TextView) findViewById(R.id.tv_config_algorithm))
						.setText(getResources()
								.getString(
										R.string.actual_pace_config_algorithm)
								+ " AES (192 Bit) CBC/CMAC");
				((PICCPACEProtocol_Settings) authProt)
						.setAlgorithm(Algorithms._AES_192);
			} else if (algorithm == 256) {
				((TextView) findViewById(R.id.tv_config_algorithm))
						.setText(getResources()
								.getString(
										R.string.actual_pace_config_algorithm)
								+ " AES (256 Bit) CBC/CMAC");
				((PICCPACEProtocol_Settings) authProt)
						.setAlgorithm(Algorithms._AES_256);
			}

			if (id >= 0 && id <= 18) {
				((TextView) findViewById(R.id.tv_config_sdp))
						.setText(getResources()
								.getString(
										R.string.actual_pace_config_sdp)
								+ " " + id);
				((PICCPACEProtocol_Settings) authProt)
						.setStandardizedDomainParameterID(id);
			}
		}

	}

}
