package com.decident.test.support;

import javax.net.ssl.X509TrustManager;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class TestTrustManager implements X509TrustManager
{
    private X509Certificate[] acceptedIssuers = null;

    public TestTrustManager() {

    }

    public TestTrustManager( X509Certificate... acceptedIssuers ) {
        this.acceptedIssuers = acceptedIssuers;
    }

    @Override
    public void checkClientTrusted(X509Certificate[] x509Certificates, String s)
            throws CertificateException {
       // no-op
    }

    @Override
    public void checkServerTrusted(X509Certificate[] x509Certificates, String s)
            throws CertificateException {
        // no-op
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return acceptedIssuers;
    }
}
