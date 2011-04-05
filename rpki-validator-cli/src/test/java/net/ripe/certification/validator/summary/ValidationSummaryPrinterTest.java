package net.ripe.certification.validator.summary;

import static org.easymock.EasyMock.createMock;
import static org.easymock.EasyMock.expect;
import static org.easymock.EasyMock.replay;
import static org.easymock.EasyMock.verify;
import static org.junit.Assert.assertEquals;

import java.math.BigInteger;

import org.joda.time.DateTime;
import org.junit.Test;

public class ValidationSummaryPrinterTest {
    
    @Test
    public void shouldPrint() {
        ValidationSummaryCollector collector  = createMock(ValidationSummaryCollector.class);
        
        String expected = "\n" +
                          "# Statistics Summary (see README for detail):\n" +
                          "# date\t\tcerts\troas\troa-asn\troa-v4\troa-v4u\troa-v6\troa-v6u\tcert-X\troa-X\n" +
                          new DateTime().toString("YYYY-MM-dd") + "\t2\t3\t6\t4\t10\t5\t1\t7\t8\n";
        
        expect(collector.getNumberOfCertificates()).andReturn(2);      
        expect(collector.getNumberOfRoas()).andReturn(3);      
        expect(collector.getNumberOfDistinctAsns()).andReturn(6);      
        expect(collector.getNumberOfDistinctRoaIPv4Prefixes()).andReturn(4);      
        expect(collector.getRoaIPv4Coverage()).andReturn(BigInteger.TEN);
        expect(collector.getNumberOfDistinctRoaIPv6Prefixes()).andReturn(5);
        expect(collector.getRoaIPv6Coverage()).andReturn(BigInteger.ONE);
        expect(collector.getNumberOfRejectedCerts()).andReturn(7);
        expect(collector.getNumberOfRejectedRoas()).andReturn(8);
        
        replay(collector);
        
        String actual = ValidationSummaryPrinter.getMessage(collector);
        assertEquals(expected, actual);
        
        verify(collector);
    }

}
