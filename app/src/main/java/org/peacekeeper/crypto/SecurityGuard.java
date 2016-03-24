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

//http://developer.android.com/training/articles/keystore.html
//http://developer.android.com/reference/android/security/keystore/KeyProtection.html
//http://www.bouncycastle.org/wiki/display/JA1/X.509+Public+Key+Certificate+and+Certification+Request+Generation
//http://www.bouncycastle.org/wiki/display/JA1/X.509+Public+Key+Certificate+and+Certification+Request+Generation#X.509PublicKeyCertificateandCertificationRequestGeneration-Version3CertificateCreation
//http://stackoverflow.com/questions/29852290/self-signed-x509-certificate-with-bouncy-castle-in-java

*/


import org.peacekeeper.exception.*;
import org.peacekeeper.util.pkUtility;
import org.slf4j.*;
import org.spongycastle.asn1.sec.SECNamedCurves;
import org.spongycastle.asn1.x500.*;
import org.spongycastle.asn1.x500.style.*;
import org.spongycastle.asn1.x509.Extension;
import org.spongycastle.cert.*;
import org.spongycastle.cert.jcajce.*;
import org.spongycastle.jce.ECNamedCurveTable;
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
import java.security.Provider.Service;
import java.security.cert.*;
import java.util.*;

// http://stackoverflow.com/questions/18244630/elliptic-curve-with-digital-signature-algorithm-ecdsa-implementation-on-bouncy
public final class SecurityGuard {
//begin static
static private final Logger mLog = LoggerFactory.getLogger(SecurityGuard.class);
static private final Provider PROVIDER = new org.spongycastle.jce.provider.BouncyCastleProvider();

static private KeyPair KEYPAIR = null;
static private KeyStore KEYSTORE = null;
static private final String ECDSA = "ECDSA", SHA256withECDSA = "SHA256withECDSA"
		, charset = "UTF-8"
		, NamedCurve = "P-256" //"secp256r1"
	    , providerName = PROVIDER.getName()
		, Alias = ".pk"
		, pubKeyAlias = "pub" + Alias
		, priKeyAlias = "pri" + Alias
		, certKeyAlias = "Cert" + Alias
		, keyStoreType = "PKCS12"
		, keyStoreFilename = keyStoreType + Alias
		, uniqID = UUID.randomUUID().toString()
		;
static private final char[] keyStorePW = "PeaceKeeperKeyStorePW".toCharArray();


//end static

private String message = null;
private byte[] hash = null, signature = null;

static void initSecurity(){ initSecurity(PROVIDER); }

//Moves provider to first place
static void initSecurity(Provider provider){
	Security.removeProvider(provider.getName());

	int insertProviderAt = Security.insertProviderAt(provider, 1);
	mLog.debug("insertProviderAt:\t" + Integer.toString(insertProviderAt)) ;
	//mLog.debug( listProviders() );
}//initSecurity

public SecurityGuard(final String message) {
	initSecurity();
	this.message = message;
}


private KeyPair getKeyPair(){

	mLog.debug("KEYPAIR " + (KEYPAIR == null ? "" : "NOT ") + "null");

	if (KEYPAIR != null){return KEYPAIR; }
	mLog.debug("KEYSTORE " + (KEYSTORE == null ? "" : "NOT ") + "null");

	if (KEYSTORE == null) { genKeyStore();}
	keyStoreContents();

	try {
		if ( KEYSTORE.containsAlias(priKeyAlias)) {
			PrivateKey privateKey = (PrivateKey) KEYSTORE.getKey(priKeyAlias, keyStorePW);
			PublicKey publicKey = (PublicKey) KEYSTORE.getKey(pubKeyAlias, keyStorePW);
			//KEYPAIR = new KeyPair(publicKey, privateKey );
		}//if
		else genKeyPair();
	}//try
	catch (KeyStoreException| NoSuchAlgorithmException| UnrecoverableEntryException X) {
		pkException CRYPTOERR = new pkException(pkErrCode.CRYPTO).set("Crypto getKeyPair err", X);
		mLog.error(CRYPTOERR.toString());
		KEYPAIR = null;
		throw CRYPTOERR;
	}

	return KEYPAIR;
}//getKeyPair

private static X500Name getX500Name(){
	return new X500NameBuilder(BCStyle.INSTANCE)
				.addRDN(BCStrictStyle.EmailAddress, "JD.John.Donaldson@gmail.com")
				.addRDN(BCStrictStyle.SERIALNUMBER, pkUtility.getInstance().getUniqDeviceID().toString())
				.addRDN(BCStrictStyle.UNIQUE_IDENTIFIER, uniqID)
				.addRDN(BCStyle.CN, Alias)
			.build();
}//getX500Name

// http://www.programcreek.com/java-api-examples/index.php?class=org.spongycastle.cert.X509v3CertificateBuilder&method=addExtension
//private static X509Certificate genRootCertificate( KeyPair kp, String CN){
private static X509Certificate genRootCertificate( KeyPair kp){
	X509Certificate certificate;
	try {
		final Calendar start = Calendar.getInstance();
		final Date now = start.getTime();
		//expires in one day - just enough time to be replaced by CA CERT
		start.add(Calendar.DATE, 1);
		final Date expire = start.getTime();


		JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(SHA256withECDSA);

		ContentSigner signer = csBuilder.build(kp.getPrivate());

/*
		DefaultAlgorithmNameFinder daf = new DefaultAlgorithmNameFinder();
		String algo = daf.getAlgorithmName( signer.getAlgorithmIdentifier() );
		mLog.debug("genroot signer.getAlgorithmIdentifier(): \t" + algo);
*/

		BigInteger serialnum = new BigInteger(80, new SecureRandom());//new Random()),

		//Is X509v3CertificateBuilder ok for a Root Cert??
		X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(
                                      getX500Name(), //builder.build(),
                                      serialnum,
                                      now, //new Date(System.currentTimeMillis() - 50000),
                                      expire,
                                      getX500Name(),
                                      kp.getPublic()
									)
								.addExtension( UniqID() )
								;
		X509CertificateHolder certHolder = certGen.build(signer);

//		algo = daf.getAlgorithmName(certHolder.getSignatureAlgorithm());
//		mLog.debug("genroot certHolder.getSignatureAlgorithm(): \t" + algo);

		certificate = new JcaX509CertificateConverter()
				              .setProvider(PROVIDER.getName())
				              .getCertificate(certHolder);
	}//try
	catch( OperatorCreationException| CertificateException| CertIOException X ) {
		pkException CRYPTOERR = new pkException(pkErrCode.CRYPTO).set("Crypto selfSignedCert gen err", X);
		mLog.error(CRYPTOERR.toString());
		throw CRYPTOERR;
	}


	//mLog.debug( "genroot kp.getPublic().getAlgorithm(): \t" + kp.getPublic().getAlgorithm() );
	//mLog.debug("certificate.getPublicKey().getAlgorithm():\t" + certificate.getPublicKey().getAlgorithm());
return certificate;
}//genRootCertificate()

//http://stackoverflow.com/questions/16412315/creating-custom-x509-v3-extensions-in-java-with-bouncy-castle
//http://www.ietf.org/rfc/rfc3280.txt
private static Extension UniqID(){
	byte[] UniqID = null;
	try {
		String id = pkUtility.getInstance().getUniqDeviceID().toString();
		UniqID = id.getBytes(charset);
		mLog.debug("getUniqDeviceID():\t" + id);
	} catch (java.io.UnsupportedEncodingException e) {
		e.printStackTrace();
	}
//	ASN1ObjectIdentifier asn1iod = new ASN1ObjectIdentifier("1.2.3.4");
//	return new Extension( asn1iod, true, UniqID);
return new Extension( Extension.subjectAlternativeName, true, UniqID);
}//UniqID


public static void genKeyStore() {
	try {
		KEYSTORE = KeyStore.getInstance(keyStoreType, providerName);
		KEYSTORE.load(null, null);
		genKeyPair();
		storeKey();
		X509Certificate[] selfSignedCert = new X509Certificate[1];
		selfSignedCert[0] = genRootCertificate(KEYPAIR);

		KEYSTORE.setCertificateEntry(certKeyAlias, selfSignedCert[0]);
		KEYSTORE.setKeyEntry(priKeyAlias, KEYPAIR.getPrivate(), keyStorePW, selfSignedCert);
		//KEYSTORE.setKeyEntry(pubKeyAlias, KEYPAIR.getPublic(), keyStorePW, selfSignedCert);

		mLog.debug("KEYSTORE init'd");
	}
	catch (KeyStoreException| NoSuchProviderException
	       | IOException| NoSuchAlgorithmException| CertificateException    X) {
		pkException CRYPTOERR = new pkException(pkErrCode.CRYPTO).set("genKeyStore err", X);;
		mLog.error(CRYPTOERR.toString());
		throw CRYPTOERR;
	}
}//genKeyStore

private static void genKeyPair(){
	KeyPairGenerator kpg;
	try {
		kpg = KeyPairGenerator.getInstance(ECDSA, providerName );
	}
	catch (NoSuchAlgorithmException| NoSuchProviderException X) {
		pkException CRYPTOERR = new pkException(pkErrCode.CRYPTO).set("genKeyPair err", X);;
		mLog.error(CRYPTOERR.toString());
		throw CRYPTOERR;
	}
	try {
		ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec(NamedCurve);
		kpg.initialize(ecSpec, new SecureRandom());
/*
			kpg.initialize(
			new android.security.keystore.KeyGenParameterSpec.Builder(
			Alias,
			android.security.keystore.KeyProperties.PURPOSE_SIGN)
			.setAlgorithmParameterSpec(new java.security.spec.ECGenParameterSpec(NamedCurve))
			.setDigests(android.security.keystore.KeyProperties.DIGEST_SHA256
			)
			// Only permit the private key to be used if the user authenticated
			// within the last five minutes.
			//.setUserAuthenticationRequired(true)
			//.setUserAuthenticationValidityDurationSeconds(5 * 60)

			.build(),
			new java.security.SecureRandom());*/
	} catch (java.security.InvalidAlgorithmParameterException X) {
		pkException CRYPTOERR = new pkException(pkErrCode.CRYPTO).set("genKeyPair initialize err", X);;
		mLog.error(CRYPTOERR.toString());
		throw CRYPTOERR;
	}

	KEYPAIR = kpg.generateKeyPair();
}//genKeyPair

//https://github.com/boeboe/be.boeboe.spongycastle/commit/5942e4794c6f950a95409f2612fad7de7cc49b33
private static void storeKey(){
//	String path = pkUtility.getInstance().getExternalStorageDirectory();
	String path = pkUtility.getInstance().getAppDataDir();

	mLog.debug("storeKey path:\t" + path);

	File file = new File(path, keyStoreFilename );
	file.getParentFile().mkdirs();
	mLog.debug("storeKey KEYSTORE file: " + file.getAbsolutePath() );

	try {
		KEYSTORE.store(new FileOutputStream(file), keyStorePW);
	}
	catch (FileNotFoundException X){
		pkException CRYPTOERR = new pkException(pkErrCode.CRYPTO).set("storeKey err", X);;
		mLog.error(CRYPTOERR.toString());
		throw CRYPTOERR; }
	catch ( CertificateException| NoSuchAlgorithmException| KeyStoreException| IOException  X){
		pkException CRYPTOERR = new pkException(pkErrCode.CRYPTO).set("storeKey err", X);;
		mLog.error(CRYPTOERR.toString());
		throw CRYPTOERR; }
}//storeKey



public byte[] getSignature(){
    if (this.signature == null)
    try {
        KeyPair keyPair = getKeyPair();
	    Signature ecdsaSign = Signature.getInstance(SHA256withECDSA);

	    ecdsaSign.initSign(keyPair.getPrivate());
        ecdsaSign.update(this.message.getBytes(charset));
        signature = ecdsaSign.sign();
} catch (NoSuchAlgorithmException| InvalidKeyException| SignatureException| UnsupportedEncodingException X)
    {   X.printStackTrace();
        pkException CRYPTOERR = new pkException(pkErrCode.CRYPTO).set("Crypto Signature err", X);
        mLog.error(CRYPTOERR.toString());
        signature = null;
        throw CRYPTOERR;
    }//catch

return signature;
}//getSignature

public boolean verify(){
    boolean verify;
    try {
	    Signature ecdsaVerify = Signature.getInstance(SHA256withECDSA);
        ecdsaVerify.initVerify(getKeyPair().getPublic());
	    ecdsaVerify.update(this.message.getBytes(charset));
        verify = ecdsaVerify.verify( getSignature() );

    } catch (NoSuchAlgorithmException| InvalidKeyException| SignatureException| UnsupportedEncodingException X)
    {   verify = false;
        pkException CRYPTOERR = new pkException(pkErrCode.CRYPTO).set("crypto verify err", X);
        mLog.error(CRYPTOERR.toString()); }

return verify;
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
public PKCS10CertificationRequest genCSR(){
    KeyPair pair = getKeyPair();
	PKCS10CertificationRequestBuilder p10Builder;
	ContentSigner signer;

	try {
		PublicKey publicKey = KEYSTORE.getCertificate(certKeyAlias).getPublicKey();
		p10Builder = new JcaPKCS10CertificationRequestBuilder(
             getX500Name()
		    , publicKey )
		    .setLeaveOffEmptyAttributes(true)
		;

		JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(SHA256withECDSA);

		signer = csBuilder.build(pair.getPrivate());
	}catch (KeyStoreException| OperatorCreationException X) {
        pkException CRYPTOERR = new pkException(pkErrCode.CRYPTO).set("CertSignRequest err", X);
        mLog.error(CRYPTOERR.toString());
        throw CRYPTOERR;
    }

	PKCS10CertificationRequest CSR = p10Builder.build(signer);
return CSR;
}//genCSR


//Get the CertSignRequest as a PEM formatted String
public String toPEM(PKCS10CertificationRequest CSR){
    StringWriter str = new StringWriter();
    JcaPEMWriter pemWriter = new JcaPEMWriter(str);
    String retVal;
    try{
        PemObject pemObject = new PemObject("CERTIFICATE REQUEST", CSR.getEncoded());
        pemWriter.writeObject(pemObject);
        pemWriter.close();
        str.close();
        retVal = str.toString();
    } catch (IOException X) {
        pkException CRYPTOERR = new pkException(pkErrCode.CRYPTO).set("toPEM err", X);
        mLog.error(CRYPTOERR.toString());
        throw CRYPTOERR; }
return retVal;
}//toPEM

static public boolean unRegister(){
	boolean retval = false;
	keyStoreContents();
	try {
		java.util.Enumeration<String> aliases = KEYSTORE.aliases();
		while (aliases.hasMoreElements() ) { KEYSTORE.deleteEntry( aliases.nextElement().toString() ); }
	} catch (Exception ignored){}

	keyStoreContents();
	return retval;
}//unRegister()

//see https://github.com/nelenkov/ecdh-kx/blob/master/src/org/nick/ecdhkx/Crypto.java
static public void listAlgorithms(String algFilter) {
	java.security.Provider[] providers = java.security.Security.getProviders();
	for (java.security.Provider p : providers) {
		String providerStr = String.format("%s/%s/%f\n", p.getName(), p.getInfo(), p.getVersion());
		mLog.debug(providerStr);
		java.util.Set<Service> services = p.getServices();
		java.util.List<String> algs = new java.util.ArrayList<String>();
		for (Service s : services) {
			boolean match = true;
			if (algFilter != null) {
				match = s.getAlgorithm().toLowerCase()
						        .contains(algFilter.toLowerCase());
			}

			if (match) {
				String algStr = String.format("\t%s/%s/%s", s.getType(),
						                             s.getAlgorithm(), s.getClassName());
				algs.add(algStr);
			}
		}


		java.util.Collections.sort(algs);
		for (String alg : algs) {
			mLog.debug("\t" + alg);
		}
		mLog.debug("");
	}
}//listAlgorithms


static public void listCurves() {
	mLog.debug("Supported named curves:");
	java.util.Enumeration<?> names = SECNamedCurves.getNames();
	while (names.hasMoreElements()) { mLog.debug( "\t" + names.nextElement()); }
}//listCurves


private static void keyStoreContents() {
	try {
		Enumeration<String> aliases = KEYSTORE.aliases();

		mLog.debug((aliases.hasMoreElements() ? "" : "Empty") + "KEYSTORE contents" );
		while (aliases.hasMoreElements() ) { mLog.debug(":\t" + aliases.nextElement().toString() ); }
	} catch (Exception X) { mLog.debug("Empty KEYSTORE contents" ); }
}//keyStoreContents

static public String listProviders(){
	Provider[] providers = Security.getProviders();
	StringBuilder list = new StringBuilder().append("Num providers: " + providers.length );
	int i = 0;
	for (Provider p : providers){
		list.append("\n\tProvider" + ++i + ": " + p.getName() + "\t info: " + p.getInfo());
		Set<Provider.Service> services = p.getServices();
		list.append("\t\tNum services: " + services.size());
		int k = 0;
		for (Service s : services ){
			list.append("\n\t\t\tService" + ++k + ": " + "\ttype: " + s.getType() + "\talgo: " + s.getAlgorithm());
		}
	}

return list.toString();
}//listProviders

}//class SecurityGuard

