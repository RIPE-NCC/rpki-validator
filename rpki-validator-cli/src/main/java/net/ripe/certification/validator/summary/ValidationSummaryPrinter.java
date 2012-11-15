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
package net.ripe.certification.validator.summary;

import org.joda.time.DateTime;

public final class ValidationSummaryPrinter {
    
    private ValidationSummaryPrinter() {}
    
    public static String getMessage(ValidationSummaryCollector collector) {
        StringBuilder messageBuilder = new StringBuilder();
        
        messageBuilder.append("\n");
        messageBuilder.append("# Statistics Summary (see README for detail):\n");
        messageBuilder.append("# date\t\tcerts\troas\troa-asn\troa-v4\troa-v4u\troa-v6\troa-v6u\tcert-X\troa-X\n");
        
        messageBuilder.append(new DateTime().toString("YYYY-MM-dd") + "\t");
        messageBuilder.append(collector.getNumberOfCertificates() + "\t");
        messageBuilder.append(collector.getNumberOfRoas() + "\t");
        messageBuilder.append(collector.getNumberOfDistinctAsns() + "\t");
        messageBuilder.append(collector.getNumberOfDistinctRoaIPv4Prefixes() + "\t");
        messageBuilder.append(collector.getRoaIPv4Coverage() + "\t");
        messageBuilder.append(collector.getNumberOfDistinctRoaIPv6Prefixes() + "\t");
        messageBuilder.append(collector.getRoaIPv6Coverage() + "\t");
        messageBuilder.append(collector.getNumberOfRejectedCerts() + "\t");
        messageBuilder.append(collector.getNumberOfRejectedRoas() + "\n");
        
        return messageBuilder.toString();
    }

}
