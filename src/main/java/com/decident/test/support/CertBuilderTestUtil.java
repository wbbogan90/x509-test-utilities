package com.decident.test.support;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.LocalDate;
import java.time.ZoneId;
import java.util.*;

public class CertBuilderTestUtil
{
    final static Logger log = LoggerFactory.getLogger(CertBuilderTestUtil.class);

    public static String SIGNATURE_ALGORITHM = "SHA256withRSA";
    public static String PROVIDER = "BC";

    private X500Name caIssuer;
    private KeyPair caKeyPair;
    private X509Certificate caCertificate;
    private Provider bcProvider = new BouncyCastleProvider();

    public CertBuilderTestUtil()
    {
        Security.addProvider(bcProvider);
    }

    public CertBuilderTestUtil(X500Name caIssuer)
    {
        Security.addProvider(bcProvider);
        this.caIssuer = caIssuer;
        this.caKeyPair = getKeyPair();
        this.caCertificate = getRootCACert();
    }

    public void setCaIssuer(X500Name caIssuer)
    {
        this.caIssuer = caIssuer;
        this.caKeyPair = getKeyPair();
        this.caCertificate = getRootCACert();
    }

    public SSLContext generateSSLContext(KeyStore keystore, String password)
    {
        try
        {
            KeyManagerFactory keyManagerFactory = KeyManagerFactory.getInstance(
                    KeyManagerFactory.getDefaultAlgorithm());
            keyManagerFactory.init(keystore, password.toCharArray());
            KeyManager[] keyManagers = keyManagerFactory.getKeyManagers();

            TrustManager[] trustManagers = new TrustManager[1];
            trustManagers[0] = new TestTrustManager( caCertificate );

            SSLContext ctx = SSLContext.getInstance("TLSv1.2");
            ctx.init( keyManagers, trustManagers, getSecureRandom() );


            return ctx;
        }
        catch (NoSuchAlgorithmException e)
        {
            log.error("NoSuchAlgorithmException when getting SSLContext. Error: {}", e);
            throw new RuntimeException(e);
        }
        catch (UnrecoverableKeyException e)
        {
            log.error("UnrecoverableKeyException when getting SSLContext. Error: {}", e);
            throw new RuntimeException(e);
        }
        catch (KeyStoreException e)
        {
            log.error("KeyStoreException when getting SSLContext. Error: {}", e);
            throw new RuntimeException(e);
        }
        catch (KeyManagementException e)
        {
            log.error("KeyManagementException when getting SSLContext. Error: {}", e);
            throw new RuntimeException(e);
        }
    }

    public KeyStore generateKeyStore(X500Name subject, String alias, String password, CertType certType)
    {
        KeyPair subjectKeyPair = getKeyPair();
        PrivateKey subjPrivateKey = subjectKeyPair.getPrivate();
        X509Certificate[] certChain = new X509Certificate[2];

        certChain[0] = getX509Cert( subject, subjectKeyPair, certType );
        certChain[1] = caCertificate;

        String keystoreType =  (certType == CertType.CLIENT) ? "PKCS12":"JKS";

        KeyStore ks;
        try
        {
            ks = KeyStore.getInstance(keystoreType);
        }
        catch (KeyStoreException e)
        {
            log.error("KeyStoreException when getting keystore instance.  Keystore type: {}. Error: {}", keystoreType, e);
            throw new RuntimeException(e);
        }
        try {
            ks.load(null, password.toCharArray());
        } catch (Exception e) {
            log.error("Exception when loading keystore with keystore password. Error: {}", e);
            throw new RuntimeException(e);
        }
        try {
            ks.setKeyEntry(alias, subjPrivateKey, password.toCharArray(), certChain);
        } catch (KeyStoreException e) {
            log.error("KeyStoreException when setting subject key entry.  Error: {}", e);
            throw new RuntimeException(e);
        }

        return ks;
    }

    private X509Certificate getRootCACert()
    {
        Date notBefore = asDate(LocalDate.now().minusDays(1));
        Date notAfter = asDate(LocalDate.now().plusYears(10));
        SecureRandom sr = getSecureRandom();
        BigInteger serial = new BigInteger(64, sr );
        JcaX509CertificateConverter certConverter = new JcaX509CertificateConverter();

        JcaX509ExtensionUtils extensionUtils = null;
        try {
            extensionUtils = new JcaX509ExtensionUtils();
        } catch (NoSuchAlgorithmException e) {
            log.error("NoSuchAlgorithmException when creating JcaX509ExtensionUtils instance.  Error: {}", e);
            throw new RuntimeException(e);
        }

        JcaX509v3CertificateBuilder certbuilder = new JcaX509v3CertificateBuilder(caIssuer, serial, notBefore, notAfter, caIssuer, caKeyPair.getPublic());
        ContentSigner cs = null;
        try {
            cs = (new JcaContentSignerBuilder(SIGNATURE_ALGORITHM)).setProvider(PROVIDER).setSecureRandom(sr).build(caKeyPair.getPrivate());
        } catch (OperatorCreationException e) {
            log.error("OperatorCreationException in getX509CertHolder() when creating content signer.  Error {}", e);
            throw new RuntimeException(e);
        }

        KeyPurposeId[] extendedKeyUsages = new KeyPurposeId[2];
        extendedKeyUsages[0] = KeyPurposeId.id_kp_OCSPSigning;
        extendedKeyUsages[1] = KeyPurposeId.id_kp_serverAuth;
        KeyUsage caKeyUsage = new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign);
        try {
            certbuilder.addExtension(Extension.subjectKeyIdentifier, false, extensionUtils.createSubjectKeyIdentifier(caKeyPair.getPublic()));
            certbuilder.addExtension(Extension.authorityKeyIdentifier, false, extensionUtils.createAuthorityKeyIdentifier(caKeyPair.getPublic()));
            certbuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
            certbuilder.addExtension(Extension.keyUsage, false, caKeyUsage);
            certbuilder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(extendedKeyUsages));
        } catch (CertIOException e) {
            log.error("CertIOException in getX509CertHolder() when adding extensions for CA cert.  Error: {}", e);
            throw new RuntimeException(e);
        }

        X509Certificate cert;
        try {
            cert = certConverter.getCertificate( certbuilder.build(cs) );
        } catch (CertificateException e) {
            log.error("CertificateException when converting X509CertBuilder for CA cert.  Error: {}", e);
            throw new RuntimeException(e);
        }

        return cert;
    }


    private X509Certificate getX509Cert(X500Name subject, KeyPair subjectKeyPair, CertType certType )
    {
        Date notBefore = asDate(LocalDate.now().minusDays(1));
        Date notAfter = asDate(LocalDate.now().plusYears(3));
        SecureRandom sr = getSecureRandom();
        BigInteger serial = new BigInteger(64, sr );
        JcaX509CertificateConverter certConverter = new JcaX509CertificateConverter();

        JcaX509ExtensionUtils extensionUtils = null;
        try {
            extensionUtils = new JcaX509ExtensionUtils();
        } catch (NoSuchAlgorithmException e) {
            log.error("NoSuchAlgorithmException when creating JcaX509ExtensionUtils instance.  Error: {}", e);
            throw new RuntimeException(e);
        }

        JcaX509v3CertificateBuilder certbuilder = new JcaX509v3CertificateBuilder(caIssuer, serial, notBefore, notAfter, subject, subjectKeyPair.getPublic());
        ContentSigner cs = null;
        try {
            cs = (new JcaContentSignerBuilder(SIGNATURE_ALGORITHM)).setProvider(PROVIDER).setSecureRandom(sr).build(caKeyPair.getPrivate());
        } catch (OperatorCreationException e) {
            log.error("OperatorCreationException in getX509CertHolder() when creating content signer.  Error {}", e);
            throw new RuntimeException(e);
        }

        KeyUsage keyUsage = new KeyUsage(KeyUsage.keyEncipherment | KeyUsage.dataEncipherment | KeyUsage.keyAgreement | KeyUsage.digitalSignature);
        try {
            certbuilder.addExtension(Extension.subjectKeyIdentifier, false, extensionUtils.createSubjectKeyIdentifier(subjectKeyPair.getPublic()));
            certbuilder.addExtension(Extension.authorityKeyIdentifier, false, extensionUtils.createAuthorityKeyIdentifier(caKeyPair.getPublic()));
            certbuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
            certbuilder.addExtension(Extension.keyUsage, false, keyUsage);
            if ( certType == CertType.CLIENT )
            {
                certbuilder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_clientAuth));
            }
            else
            {
                certbuilder.addExtension(Extension.extendedKeyUsage, false, new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth));
            }
        } catch (CertIOException e) {
            log.error("CertIOException in getX509CertHolder() when adding extensions for user cert.  Error: {}", e);
            throw new RuntimeException(e);
        }

        X509Certificate cert;
        try {
            cert = certConverter.getCertificate( certbuilder.build(cs) );
        } catch (CertificateException e) {
            log.error("CertificateException when converting X509CertBuilder for CA cert.  Error: {}", e);
            throw new RuntimeException(e);
        }

        return cert;
    }

    private SecureRandom getSecureRandom( )
    {
        SecureRandom random = new SecureRandom();
        byte bytes[] = new byte[20];
        random.nextBytes(bytes);

        return random;
    }

    private KeyPair getKeyPair( )
    {
        KeyPair kp = null;
        KeyPairGenerator kpg = null;
        try
        {
            kpg = KeyPairGenerator.getInstance("RSA", PROVIDER);
            kpg.initialize( 2048, getSecureRandom() );
        }
        catch (NoSuchAlgorithmException e)
        {
            log.error("NoSuchAlgorithmException when initializing KeyPairGenerator. Error: {}", e);
            throw new RuntimeException(e);
        }
        catch (NoSuchProviderException e)
        {
            log.error("NoSuchProviderException when initializing KeyPairGenerator. Error: {}", e);
            throw new RuntimeException(e);
        }

        return kpg.generateKeyPair();
    }

    private Date asDate(LocalDate localDate)
    {
        return Date.from(localDate.atStartOfDay().atZone(ZoneId.systemDefault()).toInstant());
    }

}
