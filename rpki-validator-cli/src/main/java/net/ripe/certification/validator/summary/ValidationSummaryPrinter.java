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
