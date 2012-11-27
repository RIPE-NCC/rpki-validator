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

import net.ripe.rpki.validator.fetchers.NotifyingCertificateRepositoryObjectFetcher.Listener;

import net.ripe.ipresource.*;
import net.ripe.rpki.commons.crypto.CertificateRepositoryObject;
import net.ripe.rpki.commons.crypto.cms.roa.RoaCms;
import net.ripe.rpki.commons.crypto.cms.roa.RoaPrefix;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.validation.ValidationResult;

import java.math.BigInteger;
import java.net.URI;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;


public class ValidationSummaryCollector implements Listener {

    private static final BigInteger ROA_IPV6_PREFIX_COUNT_UNIT = BigInteger.valueOf(2l).pow(80);

    private static final BigInteger ROA_IPV4_PREFIX_COUNT_UNIT = BigInteger.valueOf(2l).pow(8);

    private int numberOfRoas = 0;

    private int numberOfCertificates = 0;

    private Set<Asn> distinctAsns = new HashSet<Asn>();

    private Set<RoaPrefix> distinctRoaIPv4Prefixes = new HashSet<RoaPrefix>();

    private Set<RoaPrefix> distinctRoaIPv6Prefixes = new HashSet<RoaPrefix>();
    
    private int numberOfRejectedRoas = 0;
    
    private int numberOfRejectedCerts = 0;


    @Override
    public void afterPrefetchFailure(URI uri, ValidationResult result) {
        // Don't care. Only provide summary for successfully retrieved objects
    }

    @Override
    public void afterPrefetchSuccess(URI uri, ValidationResult result) {
        // Don't care. Only provide summary for successfully retrieved objects
    }

    @Override
    public void afterFetchFailure(URI uri, ValidationResult result) {
        if (uri.toString().endsWith("cer")) {
            numberOfRejectedCerts++;
        } else if (uri.toString().endsWith("roa")) {
            numberOfRejectedRoas++;
        }
    }

    @Override
    public void afterFetchSuccess(URI uri, CertificateRepositoryObject object, ValidationResult result) {
        if (object instanceof RoaCms) {
            processValidRoa((RoaCms) object);
        } else if (object instanceof X509ResourceCertificate) {
            numberOfCertificates++;
        }
        // Don't care about Manifests and CRLs
    }


    private void processValidRoa(RoaCms roa) {
        numberOfRoas++;
        countDistinctRoaPrefixes(roa);
        distinctAsns.add(roa.getAsn());
    }

    private void countDistinctRoaPrefixes(RoaCms roa) {
        for (RoaPrefix prefix : roa.getPrefixes()) {
            IpResourceType type = prefix.getPrefix().getType();
            if (type == IpResourceType.IPv4) {
                distinctRoaIPv4Prefixes.add(prefix);
            } else {
                // RoaPrefix can only be IPv4 or IPv6.. nothing else.
                distinctRoaIPv6Prefixes.add(prefix);
            }
        }
    }

    int getNumberOfRoas() {
        return numberOfRoas;
    }

    int getNumberOfCertificates() {
        return numberOfCertificates;
    }

    int getNumberOfDistinctRoaIPv4Prefixes() {
        return distinctRoaIPv4Prefixes.size();
    }

    int getNumberOfDistinctRoaIPv6Prefixes() {
        return distinctRoaIPv6Prefixes.size();
    }

    int getNumberOfDistinctAsns() {
        return distinctAsns.size();
    }
    
    BigInteger getRoaIPv4Coverage() {
        IpResourceSet ipResourceSet = convertRoaPrefixSetToResourceSet(distinctRoaIPv4Prefixes);
        BigInteger coverage = calculateNumberOfAddressesContainedInIpResourceSet(ipResourceSet);

        return coverage.divide(ROA_IPV4_PREFIX_COUNT_UNIT);
    }

    BigInteger getRoaIPv6Coverage() {
        IpResourceSet ipResourceSet = convertRoaPrefixSetToResourceSet(distinctRoaIPv6Prefixes);
        BigInteger coverage = calculateNumberOfAddressesContainedInIpResourceSet(ipResourceSet);

        return coverage.divide(ROA_IPV6_PREFIX_COUNT_UNIT);
    }

    private IpResourceSet convertRoaPrefixSetToResourceSet(Set<RoaPrefix> roaPrefixes) {
        IpResourceSet ipResourceSet = new IpResourceSet();

        for (RoaPrefix roaPrefix : roaPrefixes) {
            ipResourceSet.add(roaPrefix.getPrefix());
        }
        return ipResourceSet;
    }

    private BigInteger calculateNumberOfAddressesContainedInIpResourceSet(IpResourceSet ipResourceSet) {
        BigInteger coverage = BigInteger.ZERO;

        Iterator<IpResource> iterator = ipResourceSet.iterator();

        while (iterator.hasNext()) {
            IpResource ipResource = iterator.next();

            UniqueIpResource start = ipResource.getStart();
            UniqueIpResource end = ipResource.getEnd();

            // ip range is zero based so compensate for the 0 by adding one at the end
            coverage = coverage.add(end.getValue().subtract(start.getValue())).add(BigInteger.ONE);
        }

        return coverage;
    }
    
    public int getNumberOfRejectedCerts() {
        return numberOfRejectedCerts;
    }
    
    public int getNumberOfRejectedRoas() {
        return numberOfRejectedRoas;
    }
}
