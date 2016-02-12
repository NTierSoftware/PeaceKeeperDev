package org.peacekeeper.util;
//usage: static public pkUtility mUtility;
//mUtility = pkUtility.getInstance(this);


import java.io.*;
import java.lang.reflect.*;
import java.text.SimpleDateFormat;
import java.util.*;

//import org.acra.ACRA;

import org.peacekeeper.exception.*;
import org.slf4j.*;

import android.content.*;
import android.content.res.AssetManager;
import android.net.*;
import android.net.wifi.WifiManager;
import android.os.*;
import android.preference.PreferenceManager;

//import com.ntier.util.Messages;

/**
 * @author JD see
 *    http://developer.android.com/training/basics/data-storage/files.html
 */

public class pkUtility extends ContextWrapper {

private static pkUtility mUtility;
private static final Logger	mLog	= LoggerFactory.getLogger( pkUtility.class );

private static final String		ExternalStorageState	= Environment.getExternalStorageState()
								, SHARED_PREFS_FNAME = "PK.sharedprefs"
								, ConnectionPropertiesFname = "Connection.properties"
								;


//private static LocationManager mLocMgr;
private static ConnectivityManager mConnMgr;
private AssetManager mAssetManager;
//private static SharedPreferences mSharedPreferences;
//http://possiblemobile.com/2013/06/context/

public static pkUtility getInstance(Context context){
	 if (mUtility == null) {
         //Always pass in the Application Context
//		 mUtility = new pkUtility(context.getApplicationContext());
		 mUtility = new pkUtility(context);
		 
     }

     return mUtility;
}

//This method is used for classes that have no context. It presumes that
//pkUtility has been initialized or an exception is thrown!
public static pkUtility getInstance(){
	 if (mUtility == null) {throw new pkException(pkErrCode.INITIALIZATION_NEEDED); }//ERRROR pkUtility must be initialized!
    return mUtility;
}

//private constructor prevents instantiation.  We only need/want one of these.
private pkUtility(Context context) {
	super( context );
	mConnMgr = (ConnectivityManager)getSystemService( Context.CONNECTIVITY_SERVICE );
	mAssetManager = getAssets();
	//mSharedPreferences = context.getSharedPreferences(SHARED_PREFS_FNAME, MODE_PRIVATE);
}

//public SharedPreferences getSharedPreferences(){  return mSharedPreferences;}
/* Checks if external storage is available for read and write */
public static boolean isExternalStorageWritable(){ return Environment.MEDIA_MOUNTED.equals( ExternalStorageState ); }
/* Checks if external storage is available to at least read */
public static boolean isExternalStorageReadable(){ return Environment.MEDIA_MOUNTED_READ_ONLY.equals( ExternalStorageState ); }


public static boolean isAndroidOnline(){
/* http://androidresearch.wordpress.com/2013/05/10/dealing-with-asynctask-and-screen-orientation/
 * http://developer.android.com/training/basics/network-ops/managing.html
 * http://stackoverflow.com/questions/7739624/android-connectivity-manager */

	final NetworkInfo networkInfo = mConnMgr.getActiveNetworkInfo();
	if ( networkInfo == null ){
		mLog.warn( "NO default network!" );
		return false;
	}
	mLog.trace( "network detected" );
	final boolean isConnected = networkInfo.isConnected();
	mLog.trace( "network " + (isConnected? "" : "  NOT!!  ") + "connected" );
	return isConnected;
}// isAndroidOnline()

/*
public void setMobileDataEnabled( final boolean enabled ){
//http://stackoverflow.com/questions/9871762/android-turning-on-wifi-programmatically

	final WifiManager wManager = (WifiManager)getSystemService(Context.WIFI_SERVICE);
	wManager.setWifiEnabled(enabled); 	

	try{	
		//http://stackoverflow.com/questions/11555366/enable-disable-data-connection-in-android-programmatically
	   final ConnectivityManager connMgr = (ConnectivityManager)getSystemService(Context.CONNECTIVITY_SERVICE);
	   final Class<?> conmanClass = Class.forName(connMgr.getClass().getName());
	   final Field connectivityManagerField = conmanClass.getDeclaredField("mService");
	   connectivityManagerField.setAccessible(true);
	   final Object connectivityManager = connectivityManagerField.get(connMgr);
	   final Class<?> connectivityManagerClass =  Class.forName(connectivityManager.getClass().getName());
	   final Method setMobileDataEnabledMethod = connectivityManagerClass.getDeclaredMethod("setMobileDataEnabled", Boolean.TYPE);
	   setMobileDataEnabledMethod.setAccessible(true);
	
	   setMobileDataEnabledMethod.invoke(connectivityManager, Boolean.valueOf(enabled));
	}
	catch( Exception e ){ mLog.error( "ERROR", e ); }
}//setMobileDataEnabled
*/


public String deviceInfo(){
	// http://stackoverflow.com/questions/8284706/send-email-via-gmail
	String packageName = getPackageName(),
			 versionName = "version Name|Number unknown!", 
			 versionCode = versionName;

	try{
		final android.content.pm.PackageInfo pinfo = getPackageManager().getPackageInfo( packageName, 0 );
		versionName = "version Name: " + pinfo.versionName;
		versionCode = "v." + pinfo.versionCode;
	}
	catch( android.content.pm.PackageManager.NameNotFoundException e ){
		mLog.error( "getPackageInfo getPackageName not found: " + packageName, e );
	}

	return new StringBuilder().append( "\n************ Device info ***********" ).
												//append( "\nApplication name:\t"). append( Messages.getString( "ApplicationName" ) ).
												append( "\nversionCode:\t" ).append( versionCode ).
												append( "\nversionName:\t" ).append( versionName ).
												append( "\npackage:\t" ).append( packageName ).
												append( "\nBrand:\t" ).append( Build.BRAND ).
												append( "\nDevice:\t" ).append( Build.DEVICE ).
												append( "\nModel:\t" ).append( Build.MODEL ).
												append( "\nManufactr:\t" ).append( Build.MANUFACTURER ).
												append( "\nBuild.USER:\t" ).append( Build.USER ).
												append( "\nRadioVersion:\t" ).append( Build.getRadioVersion() ).
												append( "\nId:\t" ).append( Build.ID ).
												append( "\nProduct:\t" ).append( Build.PRODUCT ).

												append( "\n************ Firmware ************\n" ).
												append( "\nRelease:\t" ).append( Build.VERSION.RELEASE ).
												append( "\nIncremental:\t" ).append( Build.VERSION.INCREMENTAL ).
												append( "\nCodeName:\t" ).append( Build.VERSION.CODENAME ).
												append( "\nSDK:\t" ).append( Build.VERSION.SDK_INT ).
												append( "\nBOARD:\t" ).append( Build.BOARD ).
												append( "\nBOOTLOADER:\t" ).append( Build.BOOTLOADER ).
												append( "\nCPU_ABI:\t" ).append( Build.CPU_ABI ).
												append( "\nCPU_ABI2:\t" ).append( Build.CPU_ABI2 ).
												append( "\nDISPLAY:\t" ).append( Build.DISPLAY ).
												append( "\nFINGERPRINT:\t" ).append( Build.FINGERPRINT ).
												append( "\nHARDWARE:\t" ).append( Build.HARDWARE ).
												append( "\nHOST:\t" ).append( Build.HOST ).
												append( "\nSERIAL:\t" ).append( Build.SERIAL ).
												append( "\nTAGS:\t" ).append( Build.TAGS ).
												append( "\nTYPE:\t" ).append( Build.TYPE ).

												append( "\n************ Environment ************\n" ).
												append(Environment.DIRECTORY_ALARMS).
												append(Environment.DIRECTORY_DCIM).
												//append(Environment.DIRECTORY_DOCUMENTS).
												append(Environment.DIRECTORY_DOWNLOADS).
												append(Environment.DIRECTORY_MOVIES).
												append(Environment.DIRECTORY_MUSIC).
												append(Environment.DIRECTORY_NOTIFICATIONS).
												append(Environment.DIRECTORY_PICTURES).
												append(Environment.DIRECTORY_PODCASTS).
												append(Environment.DIRECTORY_RINGTONES).
												append(Environment.MEDIA_BAD_REMOVAL).
												append(Environment.MEDIA_CHECKING).
												append(Environment.MEDIA_MOUNTED).
												append(Environment.MEDIA_MOUNTED_READ_ONLY).
												append(Environment.MEDIA_NOFS).
												append(Environment.MEDIA_REMOVED).
												append(Environment.MEDIA_SHARED).
												//append(Environment.MEDIA_UNKNOWN).
												append(Environment.MEDIA_UNMOUNTABLE).
												append(Environment.MEDIA_UNMOUNTED).
												append(Environment.getExternalStorageState()).
												append(Environment.isExternalStorageEmulated()).
												append(Environment.isExternalStorageRemovable()).
												append(Environment.getDataDirectory()).
												append(Environment.getDownloadCacheDirectory()).
												append(Environment.getExternalStorageDirectory()).
												append(Environment.getRootDirectory()).
												
												append( "\n************************\n" ).
												append( "\n\n\nYou may also enter your (optional) message here:\n" ).
	toString();

}// deviceInfo()

public static String AboutDevice(){
// http://www.herongyang.com/Android/System-Information-android-os-Environment-Class.html
	StringBuilder AboutDevice = new StringBuilder().
										append( "\n************ System properties ************\n" );

	Properties props = System.getProperties();
	Enumeration e = props.propertyNames();
	while ( e.hasMoreElements() ){
		String nextElem = (String)e.nextElement();
		AboutDevice.append( nextElem ).
						append( ":\t" ).
						append( props.getProperty( nextElem ) ).
						append( "\n" );
	}

	AboutDevice.append( "\n************ Environment ************\n" );

	Map envs = System.getenv();
/*	Set keys = envs.keySet();
	Iterator i = keys.iterator();  */	
	Iterator i = envs.keySet().iterator();
	while ( i.hasNext() ){
		String nextKey = (String)i.next();
		AboutDevice.append( nextKey ).
						append( ":\t" ).
						append( (String)envs.get( nextKey ) ).
						append( "\n" );
	}

	AboutDevice.append( "\ndata dir:\t" ).
					append( Environment.getDataDirectory().getPath()).
					append( "\ndownload cache dir:\t" ).
					append( Environment.getDownloadCacheDirectory().getPath()).
					append( "\nExternal Storage dir:\t" ).
					append( Environment.getExternalStorageDirectory().getPath()).
					append( "\nRoot dir:\t" ).
					append( Environment.getRootDirectory().getPath()).
					append("\nExternalStorageState:\t").
					append(Environment.getExternalStorageState()).
					append("\nisExternalStorageEmulated?:\t").
					append(Environment.isExternalStorageEmulated()).
					append("\nisExternalStorageRemovable?:\t").
					append(Environment.isExternalStorageRemovable() + "\n\n" )
					;


	return AboutDevice.toString();
}


/*
public void sendEmail(){
	// http://stackoverflow.com/questions/8284706/send-email-via-gmail
	final String emailSubject = new StringBuilder().append( Messages.getString( "ApplicationName" )).
																	toString(),
				 emailBody = AboutDevice();


	final Intent emailIntent = new Intent( Intent.ACTION_SENDTO,
										   Uri.fromParts( "mailto",
											Messages.getString( "emailAddr" ),
											null ) );

	emailIntent.putExtra( Intent.EXTRA_BCC, "GAELdb.help@gmail.com" )
					.putExtra( Intent.EXTRA_SUBJECT, emailSubject )
					.putExtra( Intent.EXTRA_TEXT, emailBody );

	startActivity( Intent.createChooser( emailIntent, "Send email:" ) );
}// sendEmail()
*/


public Properties getPropertiesFromAssets(String AssetFilename){
	Properties properties = null; 
	try {		
		InputStream inputStream = mAssetManager.open(AssetFilename);
		properties = new Properties();
		properties.load(inputStream);
		inputStream.close();

	} catch (IOException  e) {
		pkException ASSETFILE_NOT_FOUND = new pkException(pkErrCode.ASSETFILE_NOT_FOUND)
									.set("AssetFilename", AssetFilename);
		throw ASSETFILE_NOT_FOUND;
	}
	
	return properties;
}//getPropertiesFromAssets

public String getServerIPaddr(){
	return PreferenceManager.getDefaultSharedPreferences(this)
			.getString("ServerIPaddr", 
			getPropertiesFromAssets(ConnectionPropertiesFname)
    		.getProperty("ServerIPaddrDefault"));
}


/*
public boolean registerDevice(boolean FORCE){
	final String Registration = "Registration",
				 notYetRegistered = "";

	String registered;
	SharedPreferences prefs = PreferenceManager.getDefaultSharedPreferences(this);
	try {
//		registered = mSharedPreferences.getString(Registration, notYetRegistered);
		registered = prefs.getString(Registration, notYetRegistered);
		
	} catch (Exception e) { registered = notYetRegistered; }
	
	//retVal indicates "Has the Device already been registered?"
	boolean retVal = registered.equals(notYetRegistered);
	if ( retVal || FORCE) {
		//GaelException DEVICE_REGISTRATION = new GaelException(GaelErrCode.DEVICE_REGISTRATION);
		//send device info via a silent exception report to the Server!
	    ACRA.getErrorReporter().handleSilentException(null);
	    
	    String registrationDateTime = 
	    		new SimpleDateFormat("yyMMddHHmmss", Locale.US)
	    			.format( Calendar.getInstance().getTime() );

	    
	    prefs.edit()
			.putString(Registration, registrationDateTime)
			.apply();	  
	    
	}//if
	return retVal; 
}//registerDevice
*/

public static enum TestResult{ OK, DBdown, Webdown, Netdown, GPSdown, MismatchedDeployment; }
public TestResult Test(){ return TestResult.Netdown; }


@Override public String toString(){ 
	return new StringBuilder()
				.append( deviceInfo() )
				.toString(); 
}//toString()

}//class pkUtility

