package com.decident.test.support;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x500.AttributeTypeAndValue;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;

import java.util.*;

public class X509TestUtil
{
    private static final ASN1ObjectIdentifier cn = BCStyle.CN;
    private static final ASN1ObjectIdentifier o = BCStyle.O;
    private static final ASN1ObjectIdentifier ou = BCStyle.OU;
    private static final ASN1ObjectIdentifier st = BCStyle.ST;
    private static final ASN1ObjectIdentifier c = BCStyle.C;
    private static final ASN1ObjectIdentifier id = BCStyle.UID;
    private static final ASN1ObjectIdentifier e = BCStyle.E;

    public static String getUid(X500Name name)
    {
        String uid = null;
        List<RDN> rdns = new ArrayList(Arrays.asList(name.getRDNs()));
        for (RDN rdn: rdns) {
            List<AttributeTypeAndValue> atvs = new ArrayList(Arrays.asList(rdn.getTypesAndValues()));
            for (AttributeTypeAndValue atv : atvs) {
                if (atv.getType().equals(BCStyle.UID))
                {
                    uid = atv.getValue().toString();
                    break;
                }
            }
        }
        return uid;
    }

    /**
     * Returns an X500Name from the component pieces that make up the relative distinguished names.
     * At a minimum, commonName is required.
     *
     * @param commonName
     * @param org
     * @param orgUnit
     * @param state
     * @param country
     * @param uid
     * @param email
     * @return
     */
    public static X500Name generateX500Name(String commonName, String org, String orgUnit,
                                            String state, String country, String uid, String email)
    {
        if (cn == null)
        {
            throw new IllegalArgumentException("CN is required to generate an X500Name");
        }
        List<RDN> rdnList = new ArrayList<>();
        rdnList.add( new RDN( cn, new DERUTF8String( commonName.trim() ) ) );
        if ( org != null ) rdnList.add( new RDN( o, new DERUTF8String( org.trim() ) ) );
        if ( orgUnit != null ) rdnList.add( new RDN( ou, new DERUTF8String( orgUnit.trim() ) ) );
        if ( state != null ) rdnList.add( new RDN( st, new DERUTF8String( state.trim() ) ) );
        if ( country != null ) rdnList.add( new RDN( c, new DERUTF8String( country.trim() ) ) );
        if ( uid != null ) rdnList.add( new RDN( id, new DERUTF8String( uid.trim() ) ) );
        if ( email != null ) rdnList.add( new RDN( e, new DERUTF8String( email.trim() ) ) );

        rdnList.removeAll(Collections.singleton(null));
        RDN[] rdns = rdnList.toArray(new RDN[rdnList.size()]);

        return new X500Name(rdns);
    }



}
