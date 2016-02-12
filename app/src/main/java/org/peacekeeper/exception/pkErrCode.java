package org.peacekeeper.exception;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
/*
import android.content.res.AssetManager;
import android.content.*;
*/

import org.peacekeeper.util.pkUtility;
//See file pkErrCodes.properties
public enum pkErrCode
//To preserve errcode numbers, you should add to the bottom and NOT from the top!
{   NULL_LOCATION
	, SYNC_FAILED
	, WEBSERVICE_POST_FAILED
	, BAD_PKL_TABLE_URI
	, INSERT_FAILED
	, TOO_MANY_ACCOUNTS
	, ACCOUNT_CREATION_ERROR
	, ACCOUNT_VERIFICATION_ERROR
	, MISSING_DDL
	, ASSETFILE_NOT_FOUND
	, BAD_SQLLITE_PRAGMA
    , CRYPTO
	, INITIALIZATION_NEEDED //The programmer failed to initialize pkUtility()with pkUtility.getInstance(context);
	;

    public final String mErrMsg;
	private final String name = name();

	private static final int errNumIncrement = 9000;
	public final int errNum = errNumIncrement + ordinal();

	private final Logger mLog = LoggerFactory.getLogger( pkErrCode.class );
	private final static String BADEXCEPTION = ": This PeaceKeeper exception could not be defined! (check assetfile pkErrCodes.properties)(or confirm programmer pkUtility.getInstance(this)"; ;
	
	private pkErrCode() {
		if (name == "INITIALIZATION_NEEDED") {
			mErrMsg = "The programmer did not init pkUtility with pkUtility.getInstance(context)";
			return;
		}
		
		
		boolean badException = false;
		
		String tmpMsg = BADEXCEPTION ;
		try {
            Properties properties = pkUtility.getInstance().getPropertiesFromAssets("pkErrCodes.properties");
			tmpMsg = properties.getProperty( name );
		} 
		catch (Exception e) {
			badException = true;
			tmpMsg += name ; 
		}
		finally {mErrMsg = (tmpMsg == null)? name : tmpMsg;}		
		
		if (badException) mLog.error( new pkException(this).toString() );
	}//cstr private pkErrCode()

	
	private String toString;
	@Override
	public String toString() {
		if (toString == null) 
			toString = new StringBuilder()
					.append( " errNum: " )
					.append( errNum )
					.append( ": " )
					.append( name )
					.append( ": " )
					.append( mErrMsg )
					.toString();

		return toString; 
	}

/*
    static private Properties getPropertiesFromAssets(String AssetFilename){
        Properties properties = null;
        try {

            InputStream inputStream = getAssets().open(AssetFilename);//TODO fix utility
            properties = new Properties();
            properties.load(inputStream);
            inputStream.close();

        } catch (IOException e) {
            pkException ASSETFILE_NOT_FOUND = new pkException(pkErrCode.ASSETFILE_NOT_FOUND)
                    .set("AssetFilename", AssetFilename);
            throw ASSETFILE_NOT_FOUND;
        }

        return properties;
    }//getPropertiesFromAssets
*/

}//enum pkErrCode

