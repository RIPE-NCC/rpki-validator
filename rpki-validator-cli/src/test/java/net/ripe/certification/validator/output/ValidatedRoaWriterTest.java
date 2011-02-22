package net.ripe.certification.validator.output;

import static org.junit.Assert.*;

import java.net.URI;
import java.util.List;

import net.ripe.certification.validator.output.ValidatedRoaWriter.RoaData;
import net.ripe.commons.certification.ValidityPeriod;
import net.ripe.commons.certification.cms.roa.RoaCms;
import net.ripe.commons.certification.cms.roa.RoaCmsObjectMother;
import net.ripe.commons.certification.validation.ValidationResult;
import net.ripe.ipresource.Asn;

import org.joda.time.DateTime;
import org.joda.time.DateTimeZone;
import org.junit.Before;
import org.junit.Test;

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
