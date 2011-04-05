package net.ripe.certification.validator.summary;

import java.math.BigInteger;
import java.net.URI;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;

import net.ripe.certification.validator.fetchers.NotifyingCertificateRepositoryObjectFetcher.FetchNotificationCallback;
import net.ripe.commons.certification.CertificateRepositoryObject;
import net.ripe.commons.certification.cms.roa.RoaCms;
import net.ripe.commons.certification.cms.roa.RoaPrefix;
import net.ripe.commons.certification.validation.ValidationResult;
import net.ripe.commons.certification.x509cert.X509ResourceCertificate;
import net.ripe.ipresource.Asn;
import net.ripe.ipresource.IpResource;
import net.ripe.ipresource.IpResourceSet;
import net.ripe.ipresource.IpResourceType;
import net.ripe.ipresource.UniqueIpResource;


public class ValidationSummaryCollector implements FetchNotificationCallback {

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
