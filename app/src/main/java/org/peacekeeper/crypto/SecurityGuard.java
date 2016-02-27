//http://developer.android.com/training/articles/keystore.html
//http://developer.android.com/reference/android/security/keystore/KeyProtection.html
//http://www.bouncycastle.org/wiki/display/JA1/X.509+Public+Key+Certificate+and+Certification+Request+Generation
//http://www.bouncycastle.org/wiki/display/JA1/X.509+Public+Key+Certificate+and+Certification+Request+Generation#X.509PublicKeyCertificateandCertificationRequestGeneration-Version3CertificateCreation
//http://stackoverflow.com/questions/29852290/self-signed-x509-certificate-with-bouncy-castle-in-java


package org.peacekeeper.crypto;
/*PeaceKeeper Cryptographic Security Policy:

        Asymmetric Key Generation : ECDSA with 256 bits
        Asymmetric Signature : ECDSA for P-256
        SecurityGuard Digest : SHA-256
        Symmetric Key Generation : AES
        Symmetric Key Length : 256
        Symmetric Encryption : AES in CTR (Counter) mode, with appended HMAC.
        Certificate Format : X.509v3
        Random ID Size : 256 bits from /dev/urandom.
        Password Encryption : bcrypt
*/

import android.security.keystore.*;

import org.peacekeeper.exception.*;
import org.slf4j.*;
import org.spongycastle.asn1.x500.*;
import org.spongycastle.asn1.x500.style.BCStrictStyle;
import org.spongycastle.cert.*;
import org.spongycastle.cert.jcajce.*;
import org.spongycastle.jce.ECNamedCurveTable;
import org.spongycastle.jce.provider.BouncyCastleProvider;
import org.spongycastle.jce.spec.ECParameterSpec;
import org.spongycastle.openssl.jcajce.JcaPEMWriter;
import org.spongycastle.operator.*;
import org.spongycastle.operator.jcajce.JcaContentSignerBuilder;
import org.spongycastle.pkcs.*;
import org.spongycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.spongycastle.util.io.pem.PemObject;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.util.*;

// http://stackoverflow.com/questions/18244630/elliptic-curve-with-digital-signature-algorithm-ecdsa-implementation-on-bouncy
public class SecurityGuard {
//begin static
static private final Logger mLog = LoggerFactory.getLogger(SecurityGuard.class);
static private KeyPair KEYPAIR = null;
static private final String SHA256withECDSA = "SHA256withECDSA", AndroidKeyStore = "AndroidKeyStore", NamedCurve = "P-256", charset = "UTF-8";
//end static

private String message = null;
private byte[] hash = null, signature = null;
private KeyStore keyStore = null;

public SecurityGuard(final String message) {
	this.message = message;
}

private void keyStoreContents() {
	try {
		Enumeration<String> aliases = keyStore.aliases();
		mLog.debug("keyStore contents:" + aliases.toString());
		while (aliases.hasMoreElements()) {
			mLog.debug(aliases.nextElement().toString());
		}
	}
	catch( Exception X ){X.printStackTrace();}
}//keyStoreContents

private KeyPair getKeyPair(final String alias){

	if (KEYPAIR != null){ return KEYPAIR; }

	if (keyStore == null){
		try {
			keyStore = KeyStore.getInstance(AndroidKeyStore);
			keyStore.load(null);
			keyStoreContents();
		}//try
		catch (KeyStoreException| IOException| NoSuchAlgorithmException| CertificateException X) {
			pkException CRYPTOERR = new pkException(pkErrCode.CRYPTO).set("Crypto keyStore load err", X);
			mLog.error(CRYPTOERR.toString());
			KEYPAIR = null;
			throw CRYPTOERR;
		}
	}

	try {
		if ( keyStore.containsAlias(alias)) {
			PrivateKey PrivateKey = (PrivateKey) keyStore.getKey(alias, null); //no password
			PublicKey publicKey = keyStore.getCertificate(alias).getPublicKey();
			KEYPAIR = new KeyPair(publicKey, PrivateKey );
		}//if
		else KEYPAIR = genKeyPair( alias );
	}//try
	catch (KeyStoreException| NoSuchAlgorithmException| UnrecoverableEntryException X) {
		pkException CRYPTOERR = new pkException(pkErrCode.CRYPTO).set("Crypto getKeyPair err", X);
		mLog.error(CRYPTOERR.toString());
		KEYPAIR = null;
		throw CRYPTOERR;
	}

	return KEYPAIR;
}//getKeyPair



// http://www.programcreek.com/java-api-examples/index.php?class=org.spongycastle.cert.X509v3CertificateBuilder&method=addExtension
private static X509Certificate genRootCertificate( KeyPair kp, String CN){
	X509Certificate certificate = null;
	try {
		X500Name x500Name = new X500NameBuilder(BCStrictStyle.INSTANCE)
				                          .addRDN(BCStrictStyle.CN, CN)
							.build();

		final Calendar start = Calendar.getInstance();
		final Date now = start.getTime();
		//expires in one day - just enough time to be replaced by CA CERT
		//TODO consider genRootCertificate(KeyPair kp, String CN, Date expire )
		start.add(Calendar.DATE, 1);
		final Date expire = start.getTime();


		X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(
                                      x500Name, //builder.build(),
                                      new BigInteger(80, new SecureRandom()), //new Random()),
                                      now, //new Date(System.currentTimeMillis() - 50000),
                                      expire,
                                      x500Name, //builder.build(),
                                      kp.getPublic()
									);

		JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(SHA256withECDSA);
		ContentSigner signer = csBuilder.build(kp.getPrivate());
		X509CertificateHolder certHolder = certGen.build(signer);

		certificate = new JcaX509CertificateConverter().getCertificate(certHolder);
	}//try
	catch( OperatorCreationException| CertificateException X ) {
		pkException CRYPTOERR = new pkException(pkErrCode.CRYPTO).set("Crypto selfSignedCert gen err", X);
		mLog.error(CRYPTOERR.toString());
		certificate = null;
		throw CRYPTOERR;
	}
	finally { return certificate; }
}//genRootCertificate()

//http://developer.android.com/reference/android/security/keystore/KeyGenParameterSpec.html
private KeyPair genKeyPair(final String alias) {
	final int  keyPurpose = KeyProperties.PURPOSE_SIGN
					             |KeyProperties.PURPOSE_DECRYPT
					             |KeyProperties.PURPOSE_ENCRYPT
					             |KeyProperties.PURPOSE_VERIFY
			   //, FiveMin = 5 * 60
					;

	final Calendar start = Calendar.getInstance();
	final Date now = start.getTime();
	start.add(Calendar.YEAR, 1);
	final Date expire = start.getTime();

/*
	KeyStore keyStore = null;
	mLog.error("CREATING STORE");
	try {
		keyStore = KeyStore.getInstance("AndroidKeyStore");
		keyStore.load(null);
		mLog.error("STORE CREATED!!!!");
	}
	catch(Exception X) {X.printStackTrace();}
*/



	//ECParameterSpec ecSpec = (ECParameterSpec)ECNamedCurveTable.getParameterSpec(NamedCurve);
	//ECParameterSpec ecSpec = new ECGenParameterSpec("secp256r1")
	KeyPair keyPair;


	try {

		KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", BouncyCastleProvider.PROVIDER_NAME);

/*
		AlgorithmParameterSpec alSpec = new KeyGenParameterSpec.Builder(alias, keyPurpose )
											//.setAlgorithmParameterSpec( new ECGenParameterSpec(NamedCurve) )
				                                .setAlgorithmParameterSpec(new ECGenParameterSpec("secp256r1"))


				                                .setAlgorithmParameterSpec(ecSpec)
													.setDigests(KeyProperties.DIGEST_SHA256)
													.setUserAuthenticationRequired(true)
													// Only permit the private key to be used if the user authenticated within the last five minutes.
													//	              .setUserAuthenticationValidityDurationSeconds(FiveMin)
													.setKeyValidityStart(now)
													.setKeyValidityEnd(expire)
												.build();
		kpg.initialize( alSpec);
*/

		ECGenParameterSpec     ecGenSpec = new ECGenParameterSpec(NamedCurve);
		kpg.initialize(ecGenSpec, new SecureRandom());



		keyPair = kpg.generateKeyPair();






	} catch (NoSuchAlgorithmException| InvalidAlgorithmParameterException| NoSuchProviderException X) {
		mLog.error(X.getMessage());
		X.printStackTrace();
		//Crypto KeyPair gen err=[java.security.InvalidAlgorithmParameterException: parameter object not a ECParameterSpec
		pkException CRYPTOERR = new pkException(pkErrCode.CRYPTO).set("Crypto KeyPair gen err", X);
//		mLog.error(CRYPTOERR.toString());
		keyPair = null;

		throw CRYPTOERR;
	}

//	mLog.error("KEYPAIR GENERATED!?!?!");
	keyStoreContents();

// Now we import the Spongeycastle provided keypair into the AndroidKeyStore provided KeyStore.
// see http://developer.android.com/reference/android/security/keystore/KeyProtection.html

	//KeyStore keyStore;
	try {
		//keyStore = KeyStore.getInstance("AndroidKeyStore");
		//keyStore = KeyStore.getInstance(BouncyCastleProvider.PROVIDER_NAME);
		//keyStore.load(null);

		//selfSignedCert is only for initial persistence of the KeyPair. We replace it with
		// true good CA Cert later.
		X509Certificate[] selfSignedCert = new X509Certificate[1];
		selfSignedCert[0] = genRootCertificate(keyPair, alias);
		KeyStore.Entry privateKey = new PrivateKeyEntry(keyPair.getPrivate(), selfSignedCert);

		KeyStore.ProtectionParameter param = new KeyProtection.Builder( KeyProperties.PURPOSE_SIGN)
				                                     .setDigests(KeyProperties.DIGEST_SHA256)
				                                     .build();

		keyStore.setEntry( alias, privateKey, param );

	} catch (KeyStoreException X) {
//	} catch (KeyStoreException| IOException| NoSuchAlgorithmException| CertificateException X) {
		pkException CRYPTOERR = new pkException(pkErrCode.CRYPTO).set("Crypto KeyStore gen err", X);
		mLog.error(CRYPTOERR.toString());
		keyPair = null;
		throw CRYPTOERR;
	}
	finally { return keyPair; }

}//genKeyPair

private static final String testAlias = "JD test Alias";
public byte[] getSignature(){
    if (this.signature == null)
    try {
        KeyPair keyPair = this.getKeyPair(testAlias);
	    Signature ecdsaSign = Signature.getInstance(SHA256withECDSA);
        ecdsaSign.initSign(keyPair.getPrivate());
        ecdsaSign.update(this.message.getBytes(charset));
        signature = ecdsaSign.sign();
    } catch (NoSuchAlgorithmException| InvalidKeyException| UnsupportedEncodingException| SignatureException X)
    {
        pkException CRYPTOERR = new pkException(pkErrCode.CRYPTO).set("Crypto Signature err", X);
        mLog.error(CRYPTOERR.toString());
        signature = null;
        throw CRYPTOERR;
    }//catch

return signature;
}//getSignature

public boolean verify(){
    Signature ecdsaVerify = null;
    boolean retVal = false;
    try {
        ecdsaVerify = Signature.getInstance(SHA256withECDSA, BouncyCastleProvider.PROVIDER_NAME);
        ecdsaVerify.initVerify( getKeyPair(testAlias).getPublic() );
        ecdsaVerify.update(this.message.getBytes(charset));
        retVal = ecdsaVerify.verify( getSignature() );
    } catch (NoSuchAlgorithmException| NoSuchProviderException| SignatureException| UnsupportedEncodingException X)
    {   retVal = false;
        pkException CRYPTOERR = new pkException(pkErrCode.CRYPTO).set("crypto verify err", X);
        mLog.error(CRYPTOERR.toString()); }

    finally { return retVal; }
}//verify

// http://stackoverflow.com/questions/9661008/compute-sha256-hash-in-android-java-and-c-sharp?lq=1
public void setHash() throws NoSuchAlgorithmException, UnsupportedEncodingException
{   MessageDigest digest = MessageDigest.getInstance("SHA-256");
    this.hash = digest.digest(message.getBytes(charset));
}//setHash


//http://stackoverflow.com/questions/415953/how-can-i-generate-an-md5-hash/23273249#23273249
@Override
public String toString() {
    if (this.hash == null) return null;

    String hashStr = new BigInteger(1, this.hash).toString(16);

// Now we need to zero pad it if you actually want the full 32 chars.
    while (hashStr.length() < 32) { hashStr = "0" + hashStr; }


    StringBuilder retVal = new StringBuilder("SecurityGuard:\t")
                           .append(this.message)
                           .append("\tHash: ").append(hashStr);

return retVal.toString();
}

//https://msdn.microsoft.com/en-us/library/windows/desktop/aa376502(v=vs.85).aspx
// http://stackoverflow.com/questions/20532912/generating-the-csr-using-bouncycastle-api
public PKCS10CertificationRequest generateCSR(){
    KeyPair pair = this.getKeyPair(testAlias);

    X500Name subject = new X500NameBuilder( new BCStrictStyle() )
            .addRDN(BCStrictStyle.EmailAddress, "JD.John.Donaldson@gmail.com")
            .build();

    PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
            subject
            , pair.getPublic() )
            .setLeaveOffEmptyAttributes(true);

    JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(SHA256withECDSA);
    ContentSigner signer;// = null;

    try { signer = csBuilder.build(pair.getPrivate()); }
    catch (OperatorCreationException X) {
        pkException CRYPTOERR = new pkException(pkErrCode.CRYPTO).set("CSR err", X);
        mLog.error(CRYPTOERR.toString());
        throw CRYPTOERR;
    }

return p10Builder.build(signer);
}//generateCSR


//Get the CSR as a PEM formatted String
public String toPEM(PKCS10CertificationRequest CSR){
    StringWriter str = new StringWriter();
    JcaPEMWriter pemWriter = new JcaPEMWriter(str);
    String retVal = "";
    try
/*
	    (
		        StringWriter str = new StringWriter();
		        JcaPEMWriter pemWriter = new JcaPEMWriter(str);
        )
*/
    {
        PemObject pemObject = new PemObject("CERTIFICATE REQUEST", CSR.getEncoded());
        pemWriter.writeObject(pemObject);
        pemWriter.close();
        str.close();
        retVal = str.toString();
    } catch (IOException X) {
        retVal = "";
        pkException CRYPTOERR = new pkException(pkErrCode.CRYPTO).set("toPEM err", X);
        mLog.error(CRYPTOERR.toString());
        throw CRYPTOERR; }
    finally { return retVal; }
}//toPEM

public boolean unRegister(){
	boolean retval = false;
	return retval;
}//unRegister()
}//class SecurityGuard
