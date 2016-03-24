package org.peacekeeper.rest;

import android.os.AsyncTask;

import org.peacekeeper.account.Contract;
import org.peacekeeper.util.AsyncResponse;
import org.slf4j.*;

import java.io.IOException;
import java.net.URL;


public class Registrar extends AsyncTask<URL, Void, String>{
private AsyncResponse delegate=null;
//private static Contract mContract = new Contract();
static private final Logger mLog = LoggerFactory.getLogger( Registrar.class );

//Assigning call back interface through constructor
public Registrar(AsyncResponse asyncResponse) { delegate = asyncResponse; }


@Override protected String doInBackground(URL...urls ){
    mLog.debug("doInBackground():\t" + urls[0]);
    String result = null;
	WebServicePost post;
    try{
	    post = new WebServicePost(new Contract());
	    result = post.post(urls[0]);  //downloadUrl(urls[0]);
    }
    catch (IOException e) { mLog.error("doInBackground", e.getLocalizedMessage()); }

return result;
}//doInBackground



@Override protected void onPostExecute(String result){
	mLog.debug("onPostExecute");
	delegate.processFinish(result);
}//onPostExecute
}//class Registrar



/** Network connection timeout, in milliseconds. */
// private static final int NET_CONNECT_TIMEOUT_MILLIS = 15000,  // 15 seconds

/** Network read timeout, in milliseconds. */
//NET_READ_TIMEOUT_MILLIS = 10000;  // 10 seconds

/** Given a string representation of a URL, sets up a connection and gets an input stream. */
/*
    private static String downloadUrl( java.net.URL url) throws java.io.IOException {
 		java.io.InputStream in = null, ins = null;
 		String result;

         javax.net.ssl.HttpsURLConnection conn = (javax.net.ssl.HttpsURLConnection) url.openConnection();
         conn.setReadTimeout(NET_READ_TIMEOUT_MILLIS */
/* milliseconds *//*
);
         conn.setConnectTimeout(NET_CONNECT_TIMEOUT_MILLIS */
/* milliseconds *//*
);
         conn.setRequestMethod("GET");
         conn.setDoInput(true);
         // Starts the query
         conn.connect();

 		//trustEveryone(true);
 		ins = conn.getInputStream();
 		in = new java.io.BufferedInputStream(ins );
 		result = inputStreamToString(in);
 		conn.disconnect();
 		in.close();
 		ins.close();
 		return result;
     }//downloadUrl

	protected static String inputStreamToString(java.io.InputStream is) {
		StringBuilder total = new StringBuilder();

		try {
			// Wrap a BufferedReader around the InputStream
			java.io.BufferedReader rd = new java.io.BufferedReader(
					new java.io.InputStreamReader(is));
			String line;
			// Read response until the end
			while ((line = rd.readLine()) != null) {
				total.append(line);
			}
			rd.close();
		}
		catch (java.io.IOException e) { Log.e("inputStreamToString", e.getLocalizedMessage()); }

		return total.toString();
	}//inputStreamToString
*/
