/**
 * The BSD License
 *
 * Copyright (c) 2010, 2011 RIPE NCC
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
