package com.ba_picc;

import java.util.ArrayList;

import android.app.Activity;
import android.graphics.Color;
import android.os.Bundle;
import android.support.v4.app.NavUtils;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AbsListView.LayoutParams;
import android.widget.BaseAdapter;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.TextView;
import core.Logging.Entry;
import core.Logging.LogType;

/**
 * Shows all log entries
 * 
 * @author Mark Forjahn
 * 
 */
public class LogActivity extends Activity {

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_log);
		// Show the Up button in the action bar.
		setupActionBar();

		ArrayList<Entry> myArray = (ArrayList<Entry>) getIntent()
				.getSerializableExtra("logEntries");
		ListView listview = (ListView) findViewById(R.id.lv_log);

		if (myArray != null) {
			final MyListAdapter mAdapter = new MyListAdapter(
					myArray);
			listview.setAdapter(mAdapter);
		}
	}

	/**
	 * Set up the {@link android.app.ActionBar}.
	 */
	private void setupActionBar() {

		getActionBar().setDisplayHomeAsUpEnabled(true);

	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// Inflate the menu; this adds items to the action bar if it is present.
		// getMenuInflater().inflate(R.menu.log, menu);
		return true;
	}

	@Override
	public boolean onOptionsItemSelected(MenuItem item) {
		switch (item.getItemId()) {
		case android.R.id.home:
			NavUtils.navigateUpFromSameTask(this);
			return true;
		}
		return super.onOptionsItemSelected(item);
	}

	private class MyListAdapter extends BaseAdapter {

		private ArrayList<Entry> entries;

		public MyListAdapter(ArrayList<Entry> entries) {
			this.entries = entries;

		}

		@Override
		public int getCount() {
			return entries.size();
		}

		@Override
		public Object getItem(int position) {
			return entries.get(position);
		}

		@Override
		public long getItemId(int position) {
			return position;
		}

		@Override
		public View getView(int position, View convertView,
				ViewGroup parent) {
			return createViewForLogEntry(entries
					.get(position));
		}
	}

	public View createViewForLogEntry(Entry entry) {
		LinearLayout ll = new LinearLayout(LogActivity.this);
		ll.setLayoutParams(new LayoutParams(
				LayoutParams.MATCH_PARENT,
				LayoutParams.WRAP_CONTENT));
		ll.setOrientation(LinearLayout.VERTICAL);
		ll.setPadding(2, 5, 2, 5);

		TextView tvLogText = new TextView(LogActivity.this);
		tvLogText.setLayoutParams(new LayoutParams(
				LayoutParams.MATCH_PARENT,
				LayoutParams.WRAP_CONTENT));
		tvLogText.setText(entry.getLog());

		TextView tvLogState = new TextView(LogActivity.this);
		tvLogState.setLayoutParams(new LayoutParams(
				LayoutParams.MATCH_PARENT,
				LayoutParams.WRAP_CONTENT));
		tvLogState.setText("_" + entry.getLogState() + "_");

		ll.addView(tvLogState);
		ll.addView(tvLogText);

		if (entry.getLogType().equals(LogType.INFORMATION)) {
			ll.setBackgroundColor(Color.GREEN);
		} else if (entry.getLogType().equals(
				LogType.WARNING)) {
			ll.setBackgroundColor(Color.YELLOW);
		} else if (entry.getLogType().equals(LogType.ERROR)) {
			ll.setBackgroundColor(Color.RED);
		}
		return ll;

	}

}
