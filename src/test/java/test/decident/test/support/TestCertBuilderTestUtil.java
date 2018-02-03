package test.decident.test.support;

import com.decident.test.support.CertBuilderTestUtil;
import com.decident.test.support.CertType;
import com.decident.test.support.X509TestUtil;
import org.bouncycastle.asn1.x500.X500Name;
import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import java.security.KeyStore;
import java.util.UUID;

public class TestCertBuilderTestUtil
{
    private X500Name client;
    private X500Name ca;
    private CertBuilderTestUtil certBuilderTestUtil;

    @BeforeClass
    private void setup()
    {
        String org = "Mega Corporation Inc.";
        String state = "NY";
        String country = "US";
        client = X509TestUtil.generateX500Name("Joe Smith", org,
                "Finance", state, country, UUID.randomUUID().toString(), "joe.smith@megacorp.com");
        ca = X509TestUtil.generateX500Name("Mega Root CA", org,
                null, state, country, UUID.randomUUID().toString(), null);
        certBuilderTestUtil = new CertBuilderTestUtil( ca );
    }

    @Test
    public void testKeystore()
    {
        KeyStore clientKeystore = certBuilderTestUtil.generateKeyStore(client, "mykey", "password", CertType.CLIENT);
        Assert.assertNotNull( clientKeystore );
        Assert.assertEquals( clientKeystore.getType(), "PKCS12");
    }


}
