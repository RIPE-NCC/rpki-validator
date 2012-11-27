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

import net.ripe.rpki.validator.output.ValidatedRoaWriter;
import net.ripe.rpki.validator.output.ValidatedRoaWriter.RoaData;

import net.ripe.ipresource.Asn;
import net.ripe.rpki.commons.crypto.ValidityPeriod;
import net.ripe.rpki.commons.crypto.cms.roa.RoaCms;
import net.ripe.rpki.commons.crypto.cms.roa.RoaCmsObjectMother;
import net.ripe.rpki.commons.validation.ValidationResult;
import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.junit.Before;
import org.junit.Test;

import java.net.URI;
import java.util.List;

import static org.junit.Assert.assertEquals;

public class ValidatedRoaWriterTest {

    private ValidatedRoaWriter subject;

    @Before
    public void setUp() {
        subject = new ValidatedRoaWriter();
    }

    @Test
    public void shouldGetRoaDataFromRoa() {
        DateTime notValidBefore = new DateTime(2009, 1, 1, 0, 0, 0, 0, DateTimeZone.UTC);
        DateTime notValidAfter = new DateTime(2009, 2, 1, 0, 0, 0, 0, DateTimeZone.UTC);
        ValidityPeriod validityPeriod = new ValidityPeriod(notValidBefore, notValidAfter);
        RoaCms roaCms = RoaCmsObjectMother.getRoaCms(validityPeriod);

        URI testUri = URI.create("rsync://host/foo.roa");

        List<RoaData> roaDataList = RoaData.getRoaDataListFromRoaCms(testUri, roaCms);

        assertEquals(3, roaDataList.size());

        RoaData firstEntry = roaDataList.get(0);
        assertEquals("AS65000", firstEntry.getAsn());
        assertEquals("10.64.0.0/12", firstEntry.getIpRange());
        assertEquals("24", firstEntry.getMaxLength());
        assertEquals("2009-01-01 00:00:00", firstEntry.getNotValidBefore());
        assertEquals("2009-02-01 00:00:00", firstEntry.getNotValidAfter());
    }


    @Test
    public void shouldKeepDataFromAllRoaCmsObjects() {
        ValidityPeriod validityPeriod = new ValidityPeriod(new DateTime(), new DateTime().plusMonths(3));
        RoaCms roaCms1 = RoaCmsObjectMother.getRoaCms(validityPeriod, Asn.parse("AS3333"));
        RoaCms roaCms2 = RoaCmsObjectMother.getRoaCms(validityPeriod, Asn.parse("AS65000"));

        ValidationResult result = new ValidationResult();

        subject.afterFetchSuccess(URI.create("rsync://host/rao1.roa"), roaCms1, result);
        subject.afterFetchSuccess(URI.create("rsync://host/rao2.roa"), roaCms2, result);

        List<RoaData> allRoaData = subject.getAllRoaData();
        assertEquals(6, allRoaData.size());

    }


}
