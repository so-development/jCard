package com.ba_picc.sepki;

import java.io.File;
import java.io.FileInputStream;

import Management.JCardTransportClass;
import android.annotation.SuppressLint;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.DialogInterface;
import android.content.Intent;
import android.os.Bundle;
import android.os.Environment;
import android.security.KeyChain;
import android.security.KeyChainAliasCallback;
import android.view.View;
import android.view.View.OnClickListener;
import android.view.Window;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;
import android.widget.Toast;
import com.ba_picc.R;
import core.Logging.Log;
import core.Logging.LogLevel;
import core.Logging.LogState;
import core.Logging.LogType;

/**
 * Borrowed of
 * https://github.com/nelenkov/virtual-pki-card/tree/master/se-emulator and
 * adapted for project.
 * 
 */
public class PKIActivity extends Activity implements
		OnClickListener, KeyChainAliasCallback {

	private static final int INSTALL_KEY_CODE = 42;
	private static final String SE_KEY_NAME = "my_se_key";

	private TextView statusText;
	private EditText pkcs12FilenameText;
	private Button installPkcs12Button;
	private EditText pinText;
	private Button setPinButton;
	private PkiApplet pkiApplet;

	@SuppressLint("NewApi")
	@Override
	public void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);

		requestWindowFeature(Window.FEATURE_INDETERMINATE_PROGRESS);

		setContentView(R.layout.activity_pki);

		if (JCardTransportClass.getJcard() == null) {
			// Configuration possible
			Toast.makeText(
					this,
					getResources()
							.getText(
									R.string.class_started_in_config_mode),
					Toast.LENGTH_LONG).show();
		} else {
			Toast.makeText(
					this,
					getResources()
							.getText(
									R.string.class_started_in_active_mode),
					Toast.LENGTH_LONG).show();
		}

		setProgressBarIndeterminateVisibility(false);

		statusText = (TextView) findViewById(R.id.status_text);
		pkcs12FilenameText = (EditText) findViewById(R.id.pkcs12FilenameText);
		installPkcs12Button = (Button) findViewById(R.id.install_pkcs12_button);
		installPkcs12Button.setOnClickListener(this);
		pinText = (EditText) findViewById(R.id.pin_text);
		setPinButton = (Button) findViewById(R.id.set_pin_button);
		setPinButton.setOnClickListener(this);

		pkiApplet = new PkiApplet(this);
		statusText
				.setText(pkiApplet.isInitialized() ? R.string.applet_initialized
						: R.string.applet_not_initialized);

		boolean starting = false;
		if (!pkiApplet.isInitialized()
				&& JCardTransportClass.getJcard() != null) {
			AlertDialog.Builder builder = new AlertDialog.Builder(
					this);
			builder.setTitle(getResources().getString(
					R.string.information));
			builder.setMessage(
					getResources().getString(
							R.string.config_app_first))
					.setNeutralButton(
							"OK",
							new DialogInterface.OnClickListener() {
								public void onClick(
										DialogInterface dialog,
										int id) {
									finish();
								}
							});
			builder.create().show();
		} else {
			starting = true;
		}

		if (JCardTransportClass.getJcard() != null
				&& starting) {
			try {
				if (pkiApplet != null) {
					Log.addEntry("Applet running: "
							+ pkiApplet.isRunning(),
							LogType.INFORMATION,
							LogState.APPLICATION_STARTED,
							LogLevel.HIGH);
					if (pkiApplet.isRunning()) {
						Log.addEntry(
								"Applet thread alredy running, stopping",
								LogType.WARNING,
								LogState.APPLICATION_STARTED,
								LogLevel.HIGH);
						pkiApplet.stop();
					}
				}
				Log.addEntry("Starting applet...",
						LogType.INFORMATION,
						LogState.APPLICATION_STARTED,
						LogLevel.HIGH);
				pkiApplet.start(JCardTransportClass
						.getJcard());

			} catch (Exception e) {
				throw new RuntimeException(e);
			}
		}
	}

	@Override
	public void onClick(View v) {
		try {
			switch (v.getId()) {
			case R.id.install_pkcs12_button:
				String pkcs12Filename = pkcs12FilenameText
						.getText().toString().trim();
				Intent intent = KeyChain
						.createInstallIntent();
				byte[] p12 = readFile(pkcs12Filename);
				intent.putExtra(KeyChain.EXTRA_PKCS12, p12);
				intent.putExtra(KeyChain.EXTRA_NAME,
						SE_KEY_NAME);
				startActivityForResult(intent,
						INSTALL_KEY_CODE);
				break;
			case R.id.set_pin_button:
				String pin = pinText.getText().toString()
						.trim();
				if (pin != null && pin.length() != 0) {
					pkiApplet.setPin(pin);
					pinText.setText(null);
					statusText
							.setText(pkiApplet
									.isInitialized() ? R.string.applet_initialized
									: R.string.applet_not_initialized);
					Log.addEntry("Set PIN to : " + pin,
							LogType.INFORMATION,
							LogState.APPLICATION_STARTED,
							LogLevel.HIGH);
				} else {
					Toast.makeText(this,
							"Enter a non-empty PIN",
							Toast.LENGTH_SHORT).show();
				}
				break;
			default:
				//
			}
		} catch (Exception e) {
			Toast.makeText(this, e.getMessage(),
					Toast.LENGTH_LONG).show();
		}
	}

	@Override
	protected void onActivityResult(int requestCode,
			int resultCode, Intent data) {
		if (requestCode == INSTALL_KEY_CODE) {
			if (resultCode == Activity.RESULT_OK) {
				chooseKey();
			} else {
				super.onActivityResult(requestCode,
						resultCode, data);
			}
		}
		statusText
				.setText(pkiApplet.isInitialized() ? R.string.applet_initialized
						: R.string.applet_not_initialized);
	}

	private void chooseKey() {
		KeyChain.choosePrivateKeyAlias(this, this,
				new String[] { "RSA" }, null, null, -1,
				SE_KEY_NAME);
	}

	private static byte[] readFile(String filename)
			throws Exception {
		File f = new File(
				Environment.getExternalStorageDirectory(),
				filename);
		byte[] result = new byte[(int) f.length()];
		FileInputStream in = new FileInputStream(f);
		in.read(result);
		in.close();

		return result;
	}

	@Override
	public void alias(final String alias) {
		pkiApplet.setAlias(alias);
	}

}
