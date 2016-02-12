package org.peacekeeper.app;

import android.app.Application;

import org.slf4j.*;

import java.security.Provider;

import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.util.ContextInitializer;


public class pkApplication extends Application {
static private final LoggerContext		mLoggerContext	= (LoggerContext)LoggerFactory.getILoggerFactory();
static private final ContextInitializer	mContextInitializer		= new ContextInitializer( mLoggerContext );
static private final Logger				mLog	= LoggerFactory.getLogger( pkApplication.class );
static private final Provider SpongyCastleProvider = new org.spongycastle.jce.provider.BouncyCastleProvider();

static {
    java.security.Security.insertProviderAt(SpongyCastleProvider, 1);
}
//private static pkApplication mInstance;

@Override
public void onCreate() {
    super.onCreate();
//    mInstance = this;
    mLog.trace("pkApplication.OnCreate:\t "
                    + SpongyCastleProvider.getName()
                    + "\t: " + SpongyCastleProvider.getVersion()
                    + "\t: " + SpongyCastleProvider.getInfo()
    );
}


//public static synchronized pkApplication getInstance() {return mInstance; }
}//pkApplication
