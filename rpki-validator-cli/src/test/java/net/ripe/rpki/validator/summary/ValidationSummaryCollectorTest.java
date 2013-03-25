/**
 * The BSD License
 *
 * Copyright (c) 2010-2012 RIPE NCC
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *   - Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   - Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *   - Neither the name of the RIPE NCC nor the names of its contributors may be
 *     used to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
package net.ripe.rpki.validator.summary;

import net.ripe.rpki.validator.summary.ValidationSummaryCollector;

import net.ripe.ipresource.Asn;
import net.ripe.ipresource.IpRange;
import net.ripe.ipresource.IpResourceSet;
import net.ripe.rpki.commons.crypto.ValidityPeriod;
import net.ripe.rpki.commons.crypto.cms.roa.RoaCms;
import net.ripe.rpki.commons.crypto.cms.roa.RoaCmsObjectMother;
import net.ripe.rpki.commons.crypto.cms.roa.RoaPrefix;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificateTest;
import net.ripe.rpki.commons.validation.ValidationResult;
import org.joda.time.DateTime;
import org.junit.Before;
import org.junit.Test;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.assertEquals;


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

        ValidationResult unused = null;

        subject.afterFetchSuccess(URI.create("rsync://host/rao1.roa"), roaCms1, unused);
        subject.afterFetchSuccess(URI.create("rsync://host/rao2.roa"), roaCms2, unused);
        subject.afterFetchSuccess(URI.create("rsync://host/rao3.roa"), roaCms3, unused);
        
        subject.afterFetchSuccess(URI.create("rsync://host/cert1.cer"), cert1, unused);
        subject.afterFetchSuccess(URI.create("rsync://host/cert2.cer"), cert2, unused);
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
