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

import org.peacekeeper.exception.pkErrCode;
import org.peacekeeper.exception.pkException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.spongycastle.asn1.pkcs.Attribute;
import org.spongycastle.jce.ECNamedCurveTable;
import org.spongycastle.jce.spec.ECParameterSpec;
import org.spongycastle.operator.ContentSigner;
import org.spongycastle.operator.OperatorCreationException;
import org.spongycastle.operator.jcajce.JcaContentSignerBuilder;
import org.spongycastle.pkcs.PKCS10CertificationRequest;
import org.spongycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.spongycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

//import org.spongycastle.pkcs.bc.BcPKCS10CertificationRequestBuilder;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;

import javax.security.auth.x500.X500Principal;

import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.util.ContextInitializer;


// http://stackoverflow.com/questions/18244630/elliptic-curve-with-digital-signature-algorithm-ecdsa-implementation-on-bouncy
public class SecurityGuard {
//begin static
static private final LoggerContext		mLoggerContext	= (LoggerContext)LoggerFactory.getILoggerFactory();
static private final ContextInitializer	mContextInitializer		= new ContextInitializer( mLoggerContext );
static private final Logger				mLog	= LoggerFactory.getLogger( SecurityGuard.class );
static private KeyPair keyPair = null;
static private final String spongeyCastle = "SC",
                            SHA256withECDSA = "SHA256withECDSA";
//end static

private String message = null;
private byte[] hash = null, signature = null;

public SecurityGuard(final String message){ this.message = message; }

public KeyPair GenerateKeys()
{   if (keyPair == null) {
        try {
            ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("P-256");
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", spongeyCastle);
            kpg.initialize(ecSpec, new SecureRandom());
            keyPair = kpg.generateKeyPair(); }
        catch (NoSuchAlgorithmException| NoSuchProviderException| InvalidAlgorithmParameterException x)
        {   keyPair = null;
            pkException CRYPTOERR = new pkException(pkErrCode.CRYPTO).set("GenerateKeys err", x);;
            mLog.error(CRYPTOERR.toString());
            throw CRYPTOERR; }
    }//if

return keyPair;
}//GenerateKeys


public byte[] getSignature(){
    if (signature == null)
    try {
        KeyPair pair = this.GenerateKeys();
        Signature ecdsaSign = Signature.getInstance(SHA256withECDSA, spongeyCastle);
        ecdsaSign.initSign(pair.getPrivate());
        ecdsaSign.update(this.message.getBytes("UTF-8"));
        signature = ecdsaSign.sign();
    } catch (NoSuchAlgorithmException| NoSuchProviderException|
             InvalidKeyException| UnsupportedEncodingException| SignatureException x)
    {
        pkException CRYPTOERR = new pkException(pkErrCode.CRYPTO).set("Crypto Signature err", x);
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
        ecdsaVerify = Signature.getInstance(SHA256withECDSA, spongeyCastle);
        ecdsaVerify.initVerify(GenerateKeys().getPublic());
        ecdsaVerify.update(this.message.getBytes("UTF-8"));
        retVal = ecdsaVerify.verify( getSignature() );
    } catch (NoSuchAlgorithmException| NoSuchProviderException|
             SignatureException| UnsupportedEncodingException x)
    {   retVal = false;
        pkException CRYPTOERR = new pkException(pkErrCode.CRYPTO).set("crypto verify err", x);
        mLog.error(CRYPTOERR.toString()); }

    finally { return retVal; }
}//verify

// http://stackoverflow.com/questions/9661008/compute-sha256-hash-in-android-java-and-c-sharp?lq=1
public void setHash() throws NoSuchAlgorithmException, UnsupportedEncodingException
{   MessageDigest digest = MessageDigest.getInstance("SHA-256");
    this.hash = digest.digest(message.getBytes("UTF-8"));
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

    PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
                                                       new X500Principal("CN=\"JD\"  Requested Test Certificate") //CN = common name
                                                       , pair.getPublic())
                                                   .setLeaveOffEmptyAttributes(true);

    JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder(SHA256withECDSA);
    ContentSigner signer = null;
    try { signer = csBuilder.build(pair.getPrivate()); }
    catch (OperatorCreationException x) {
        pkException CRYPTOERR = new pkException(pkErrCode.CRYPTO).set("CSR err", x);
        mLog.error(CRYPTOERR.toString());
        throw CRYPTOERR;
    }

    //PKCS10CertificationRequest PKCS10csr = p10Builder.build(signer);

    //Attribute[] attr =  PKCS10csr.getAttributes();

    return p10Builder.build(signer);

}//generateCSR

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
