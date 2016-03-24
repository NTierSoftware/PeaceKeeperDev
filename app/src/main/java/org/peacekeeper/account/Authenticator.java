//See http://developer.android.com/training/sync-adapters/creating-authenticator.html
package org.peacekeeper.account;

import android.accounts.*;
import android.content.Context;
import android.os.Bundle;

//Implement AbstractAccountAuthenticator and stub out all  of its methods
public class Authenticator extends android.accounts.AbstractAccountAuthenticator {
    // Simple constructor
    public Authenticator(android.content.Context context) { super(context); }
    
    @Override // Editing properties is not supported
    public android.os.Bundle editProperties( android.accounts.AccountAuthenticatorResponse r, String s) {
    	throw new UnsupportedOperationException(); }

    
    @Override // Don't add additional accounts
    public android.os.Bundle addAccount(
            android.accounts.AccountAuthenticatorResponse r,
            String s,
            String s2,
            String[] strings,
            android.os.Bundle bundle)
	throws android.accounts.NetworkErrorException { return null; }
    
    
    @Override // Ignore attempts to confirm credentials
    public android.os.Bundle confirmCredentials(
            android.accounts.AccountAuthenticatorResponse r,
            android.accounts.Account account,
            android.os.Bundle bundle)
	throws android.accounts.NetworkErrorException { return null;     }

    
    @Override // Getting an authentication token is not supported
    public android.os.Bundle getAuthToken(
            android.accounts.AccountAuthenticatorResponse r,
            android.accounts.Account account,
            String s,
            android.os.Bundle bundle)
	throws android.accounts.NetworkErrorException { throw new UnsupportedOperationException(); }
    
    
    @Override // Getting a label for the auth token is not supported
    public String getAuthTokenLabel(String s) { throw new UnsupportedOperationException(); }

    
    @Override // Updating user credentials is not supported
    public android.os.Bundle updateCredentials(
            android.accounts.AccountAuthenticatorResponse r,
            android.accounts.Account account,
            String s, android.os.Bundle bundle)
	throws android.accounts.NetworkErrorException { throw new UnsupportedOperationException(); }

    
    @Override // Checking features for the account is not supported
    public android.os.Bundle hasFeatures(
        android.accounts.AccountAuthenticatorResponse r,
        android.accounts.Account account, String[] strings)
	throws android.accounts.NetworkErrorException { throw new UnsupportedOperationException(); }

}//class Authenticator 
