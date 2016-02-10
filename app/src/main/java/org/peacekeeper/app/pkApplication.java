package org.peacekeeper.app;

import android.app.Application;


public class pkApplication extends Application {
static { java.security.Security.insertProviderAt(new org.spongycastle.jce.provider.BouncyCastleProvider(), 1); }
//private static pkApplication mInstance;

/*
@Override
public void onCreate() {
    super.onCreate();
//    mInstance = this;
}
*/


//public static synchronized pkApplication getInstance() {return mInstance; }
}//pkApplication
