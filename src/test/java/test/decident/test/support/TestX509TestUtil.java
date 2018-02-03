package test.decident.test.support;

import com.decident.test.support.X509TestUtil;
import org.bouncycastle.asn1.x500.X500Name;
import org.testng.Assert;
import org.testng.annotations.Test;

import java.util.UUID;

public class TestX509TestUtil
{
    private String name1 = "Joe Smith";
    private String name2 = "Betty Jones";
    private String org = "Mega Corporation Inc.";
    private String orgUnit = "Finance";
    private String state = "NY";
    private String country = "US";
    private String uid1 = UUID.randomUUID().toString();
    private String uid2 = UUID.randomUUID().toString();
    private String email1 = "joe.smith@megacorp.com";
    private String email2 = "betty.jones@megacorp.com";

    @Test
    public void testX500Name()
    {
        X500Name x500Name1 = X509TestUtil.generateX500Name(name1, org, orgUnit, state, country, uid1, email1);
        String retrievedUID1 = X509TestUtil.getUid( x500Name1 );
        Assert.assertEquals(uid1, retrievedUID1);

        X500Name x500Name2 = X509TestUtil.generateX500Name(name2, org, orgUnit, state, country, uid2, email2);
        Assert.assertFalse( x500Name2.equals(x500Name1) );

        X500Name x500Name3 = X509TestUtil.generateX500Name(name1, org, orgUnit, state, country, uid1, email1);
        Assert.assertTrue( x500Name3.equals(x500Name1) );
    }
}
