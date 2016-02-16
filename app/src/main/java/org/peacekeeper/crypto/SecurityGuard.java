package org.peacekeeper.crypto;
//TODO use PEMWriter class to print

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

import org.peacekeeper.exception.*;
//import org.peacekeeper.exception.pkException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.spongycastle.asn1.x500.*;
import org.spongycastle.asn1.x500.style.BCStrictStyle;
import org.spongycastle.jce.ECNamedCurveTable;
import org.spongycastle.jce.spec.ECParameterSpec;
import org.spongycastle.operator.ContentSigner;
import org.spongycastle.operator.OperatorCreationException;
import org.spongycastle.operator.jcajce.JcaContentSignerBuilder;
import org.spongycastle.pkcs.PKCS10CertificationRequest;
import org.spongycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.spongycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import java.io.OutputStreamWriter;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.*;

import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.util.ContextInitializer;

//import org.bouncycastle.openssl.PEMWriter;
import org.spongycastle.openssl.jcajce.JcaPEMWriter;
// http://stackoverflow.com/questions/18244630/elliptic-curve-with-digital-signature-algorithm-ecdsa-implementation-on-bouncy
public class SecurityGuard {
//begin static
static private final LoggerContext		mLoggerContext	= (LoggerContext)LoggerFactory.getILoggerFactory();
static private final ContextInitializer	mContextInitializer	= new ContextInitializer( mLoggerContext );
static private final Logger				mLog = LoggerFactory.getLogger( SecurityGuard.class );
static private KeyPair keyPair = null;
static private final String SpongeyCastle = "SC",
                            SHA256withECDSA = "SHA256withECDSA",
                            charsetname = "UTF-8";
//end static

private String message = null;
private byte[] hash = null, signature = null;

public SecurityGuard(final String message){ this.message = message; }

public KeyPair GenerateKeys()
{   if (keyPair == null) {
        try {
            ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("P-256");
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDSA", SpongeyCastle );
            keyPairGenerator.initialize(ecSpec, new SecureRandom());
            keyPair = keyPairGenerator.generateKeyPair(); }
        catch (NoSuchAlgorithmException| NoSuchProviderException| InvalidAlgorithmParameterException X)
        {   keyPair = null;
            pkException CRYPTOERR = new pkException(pkErrCode.CRYPTO).set("GenerateKeys err", X);;
            mLog.error(CRYPTOERR.toString());
            throw CRYPTOERR; }
    }//if

return keyPair;
}//GenerateKeys


public byte[] getSignature(){
    if (signature == null)
    try {
        KeyPair pair = this.GenerateKeys();
        Signature ecdsaSign = Signature.getInstance(SHA256withECDSA, SpongeyCastle);
        ecdsaSign.initSign(pair.getPrivate());
        ecdsaSign.update(this.message.getBytes(charsetname));
        signature = ecdsaSign.sign();
    } catch (NoSuchAlgorithmException| NoSuchProviderException|
             InvalidKeyException| UnsupportedEncodingException| SignatureException X)
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
        ecdsaVerify = Signature.getInstance(SHA256withECDSA, SpongeyCastle);
        ecdsaVerify.initVerify(GenerateKeys().getPublic());
        ecdsaVerify.update(this.message.getBytes(charsetname));
        retVal = ecdsaVerify.verify( getSignature() );
    } catch (NoSuchAlgorithmException| NoSuchProviderException|
             SignatureException| UnsupportedEncodingException X)
    {   retVal = false;
        pkException CRYPTOERR = new pkException(pkErrCode.CRYPTO).set("crypto verify err", X);
        mLog.error(CRYPTOERR.toString()); }

    finally { return retVal; }
}//verify

// http://stackoverflow.com/questions/9661008/compute-sha256-hash-in-android-java-and-c-sharp?lq=1
public void setHash() throws NoSuchAlgorithmException, UnsupportedEncodingException
{   MessageDigest digest = MessageDigest.getInstance("SHA-256");
    this.hash = digest.digest(message.getBytes(charsetname));
}//setHash


//http://stackoverflow.com/questions/415953/how-can-i-generate-an-md5-hash/23273249#23273249
@Override
public String toString() {
    if (this.hash == null) return null;

    String hashStr = new BigInteger(1, this.hash).toString(16);

// Now we need to zero pad it if you actually want the full 32 chars.
    while (hashStr.length() < 32) { hashStr = "0" + hashStr; }


    StringBuilder retVal = new StringBuilder("SecurityGuard:\t").append(this.message)
                            .append("\tHash: ").append(hashStr);

return retVal.toString();
}

// http://stackoverflow.com/questions/20532912/generating-the-csr-using-bouncycastle-api
public PKCS10CertificationRequest generateCSR(){
    KeyPair pair = this.GenerateKeys();

    //TODO fix X500 EmailAddress
    X500Name subject = new X500NameBuilder( new BCStrictStyle() )
            .addRDN(BCStrictStyle.EmailAddress, "JD.John.Donaldson@gmail.com")
            .build();

    PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
            subject
            , pair.getPublic() )
            .setLeaveOffEmptyAttributes(true);

    JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(SHA256withECDSA);
    ContentSigner signer = null;

    try { signer = csBuilder.build(pair.getPrivate()); }
    catch (OperatorCreationException X) {
        pkException CRYPTOERR = new pkException(pkErrCode.CRYPTO).set("CSR err", X);
        mLog.error(CRYPTOERR.toString());
        throw CRYPTOERR;
    }

return p10Builder.build(signer);
}//generateCSR


public void PEMprint() {
//import org.bouncycastle.openssl.PEMWriter;


    OutputStreamWriter output = new OutputStreamWriter(System.out);
    JcaPEMWriter pem = new JcaPEMWriter(output);
    pem.writeObject(this);
    pem.close();
}//PEMprint

}//SecurityGuard

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


/* private static final int oneDay = 24 * 60 * 60 * 1000, oneYear = 365 * 24 * 60 * 60 * 1000;
    final Date now = new Date(System.currentTimeMillis();

 http://www.bouncycastle.org/wiki/display/JA1/X.509+Public+Key+Certificate+and+Certification+Request+Generation#X.509PublicKeyCertificateandCertificationRequestGeneration-Version1CertificateCreation
*/
