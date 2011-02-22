package net.ripe.certification.validator.summary;

import static org.junit.Assert.assertEquals;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;

import net.ripe.commons.certification.ValidityPeriod;
import net.ripe.commons.certification.cms.roa.RoaCms;
import net.ripe.commons.certification.cms.roa.RoaCmsObjectMother;
import net.ripe.commons.certification.cms.roa.RoaPrefix;
import net.ripe.commons.certification.validation.ValidationResult;
import net.ripe.commons.certification.x509cert.X509ResourceCertificate;
import net.ripe.commons.certification.x509cert.X509ResourceCertificateTest;
import net.ripe.ipresource.Asn;
import net.ripe.ipresource.IpRange;
import net.ripe.ipresource.IpResourceSet;

import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.Test;


public class ValidationSummaryCollectorTest {

    private ValidationSummaryCollector subject;

    @Before
    public void setUp() {
        subject = new ValidationSummaryCollector();
        
        ValidityPeriod validityPeriod = new ValidityPeriod(new DateTime(), new DateTime().plusMonths(3));
        
        List<RoaPrefix> prefixes1 = new ArrayList<RoaPrefix>();
        prefixes1.add(new RoaPrefix(IpRange.parse("10.0.0.0/24")));
        prefixes1.add(new RoaPrefix(IpRange.parse("2001:7fb:fd03::/48")));
        prefixes1.add(new RoaPrefix(IpRange.parse("001:7fb:fd02::/48")));
        RoaCms roaCms1 = RoaCmsObjectMother.getRoaCms(prefixes1, validityPeriod, Asn.parse("AS3333"));
        
        List<RoaPrefix> prefixes2 = new ArrayList<RoaPrefix>();
        prefixes2.add(new RoaPrefix(IpRange.parse("10.0.0.0/24")));
        prefixes2.add(new RoaPrefix(IpRange.parse("10.0.1.0/24")));
        prefixes2.add(new RoaPrefix(IpRange.parse("001:7fb:fd02::/48")));
        RoaCms roaCms2 = RoaCmsObjectMother.getRoaCms(prefixes2, validityPeriod, Asn.parse("AS65000"));

        List<RoaPrefix> prefixes3 = new ArrayList<RoaPrefix>();
        prefixes3.add(new RoaPrefix(IpRange.parse("10.1.0.0/16")));
        RoaCms roaCms3 = RoaCmsObjectMother.getRoaCms(prefixes3, validityPeriod, Asn.parse("AS65000"));
        
        X509ResourceCertificate cert1 = X509ResourceCertificateTest.createSelfSignedCaResourceCertificate(IpResourceSet.parse("10.0.0.0/8,001:7fb:fd02::/48"));
        X509ResourceCertificate cert2 = X509ResourceCertificateTest.createSelfSignedCaResourceCertificate(IpResourceSet.parse("10.0.0.0/8"));

        ValidationResult result = new ValidationResult();

        subject.afterFetchSuccess(URI.create("rsync://host/rao1.roa"), roaCms1, result);
        subject.afterFetchSuccess(URI.create("rsync://host/rao2.roa"), roaCms2, result);
        subject.afterFetchSuccess(URI.create("rsync://host/rao3.roa"), roaCms3, result);
        
        subject.afterFetchSuccess(URI.create("rsync://host/cert1.cer"), cert1, result);
        subject.afterFetchSuccess(URI.create("rsync://host/cert2.cer"), cert2, result);
    }

    @Test
    public void shouldCountIpV4CoverageOfRoa()
    {
        // 2*24+16
        assertEquals(258, subject.getRoaIPv4Coverage().longValue());
    }
    
    @Test
    public void shouldCountIpV6CoverageOfRoa()
    {
        assertEquals(2, subject.getRoaIPv6Coverage().longValue());
    }
    
    
    @Test
    public void shouldCountRoas() {
        assertEquals(3, subject.getNumberOfRoas());
    }
    
    @Test
    public void shouldCountRoaIPv4Prefixes() {
        assertEquals(3, subject.getNumberOfDistinctRoaIPv4Prefixes());
    }
    
    @Test
    public void shouldCountRoaIPv6Prefixes() {
        assertEquals(2, subject.getNumberOfDistinctRoaIPv6Prefixes());
    }
    
    @Test
    public void shouldCountDistinctRoaAsns() {
        assertEquals(2, subject.getNumberOfDistinctAsns());
    }
    
    
    @Test
    public void shouldCountCertificates() {
        assertEquals(2, subject.getNumberOfCertificates());
    }
    
}
