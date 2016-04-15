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
package net.ripe.rpki.validator.output;

import net.ripe.ipresource.Asn;
import net.ripe.ipresource.IpRange;
import net.ripe.rpki.commons.crypto.CertificateRepositoryObject;
import net.ripe.rpki.commons.crypto.ValidityPeriod;
import net.ripe.rpki.commons.crypto.cms.roa.RoaCms;
import net.ripe.rpki.commons.crypto.cms.roa.RoaPrefix;
import net.ripe.rpki.commons.crypto.x509cert.X509ResourceCertificate;
import net.ripe.rpki.commons.util.CsvFormatter;
import net.ripe.rpki.commons.validation.ValidationResult;
import net.ripe.rpki.validator.fetchers.NotifyingCertificateRepositoryObjectFetcher.Listener;
import org.joda.time.DateTimeZone;
import org.joda.time.format.DateTimeFormat;
import org.joda.time.format.DateTimeFormatter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;

/**
 * This writer can added to the NotifyingCertififcateRepositoryObjectFetcher
 * to keep track of routing information found in RoaCms objects.
 *
 * Note that there should be a ValidatingCROF *below* this NotifyingCROF
 * to ensure that the RoaCms objects are actually *valid*.
 */
public class ValidatedRoaWriter implements Listener {

    private static final Logger LOG = LoggerFactory.getLogger(ValidatedRoaWriter.class);

    private List<RoaData> allRoaData = new ArrayList<RoaData>();

    @Override
    public void afterFetchFailure(URI uri, ValidationResult result) {
        return;
    }

    @Override
    public void afterFetchSuccess(URI uri, CertificateRepositoryObject object, ValidationResult result) {
        if (object instanceof RoaCms) {
            List<RoaData> roaDataList = RoaData.getRoaDataListFromRoaCms(uri, (RoaCms) object);
            allRoaData.addAll(roaDataList);
        }
    }

    @Override
    public void afterPrefetchFailure(URI uri, ValidationResult result) {
        return;
    }

    @Override
    public void afterPrefetchSuccess(URI uri, ValidationResult result) {
        return;
    }

    /**
     * Writes the routing information found in the RoaCms objects that were
     * fetched.
     */
    public void writeCsvFile(File outputFile) {
        CsvFormatter formatter = new CsvFormatter();

        setHeaders(formatter);

        for (RoaData roaData: allRoaData) {
            addRow(formatter, roaData);
        }

        try {
            formatter.print(outputFile);
        } catch (IOException e) {
            LOG.error("Failed to write ROA data into csv file", e);
        }
    }

    private void setHeaders(CsvFormatter formatter) {
        formatter.addQuotedColumn("URI");
        formatter.addColumn("ASN");
        formatter.addColumn("IP Prefix");
        formatter.addColumn("Max Length");
        formatter.addColumn("Not Before");
        formatter.addColumn("Not After");
    }

    private void addRow(CsvFormatter formatter, RoaData roaData) {
        formatter.addLine(roaData.getUri(),
                            roaData.getAsn(),
                            roaData.getIpRange(),
                            roaData.getMaxLength(),
                            roaData.getNotValidBefore(),
                            roaData.getNotValidAfter());
    }

    /*
     * Used for unit testing
     */
    List<RoaData> getAllRoaData() {
        return allRoaData;
    }

    /**
     * Data object for CVS data from a RoaCms. Note that multiple objects may be needed
     * to describe a single RoaCms since a RoaCms can contain multiple prefixes that
     * should result in multiple lines in the output file..
     */
    public static final class RoaData {

        private URI uri;
        private Asn asn;
        private IpRange ipRange;
        private Integer maxLength;
        private ValidityPeriod validityPeriod;

        private DateTimeFormatter dateFormatter = DateTimeFormat.forPattern("YYYY-MM-dd HH:mm:ss").withZone(DateTimeZone.UTC);

        private RoaData(URI uri, Asn asn, IpRange ipRange, Integer maxLength, ValidityPeriod validityPeriod) {
            this.uri = uri;
            this.asn = asn;
            this.ipRange = ipRange;
            this.maxLength = maxLength;
            this.validityPeriod = validityPeriod;
        }

        public String getUri() {
            return uri.toString();
        }

        public static List<RoaData> getRoaDataListFromRoaCms(URI uri, RoaCms roaCms) {
            List<RoaData> roaDataList = new ArrayList<RoaData>();

            Asn asn = roaCms.getAsn();
            X509ResourceCertificate roaCertificate = roaCms.getCertificate();
            ValidityPeriod validityPeriod = roaCertificate.getValidityPeriod();

            for (RoaPrefix roaPrefix: roaCms.getPrefixes()) {
                IpRange ipRange = roaPrefix.getPrefix();
                Integer maxLength = roaPrefix.getMaximumLength();
                RoaData roaData = new RoaData(uri, asn, ipRange, maxLength, validityPeriod);
                roaDataList.add(roaData);
            }

            return roaDataList;
        }

        public String getAsn() {
            return asn.toString();
        }

        public String getIpRange() {
            return ipRange.toString();
        }

        public String getMaxLength() {
            if (maxLength == null) {
                return null;
            }
            return maxLength.toString();
        }

        public String getNotValidBefore() {
            return dateFormatter.print(validityPeriod.getNotValidBefore());
        }

        public String getNotValidAfter() {
            return dateFormatter.print(validityPeriod.getNotValidAfter());
        }
    }
}
