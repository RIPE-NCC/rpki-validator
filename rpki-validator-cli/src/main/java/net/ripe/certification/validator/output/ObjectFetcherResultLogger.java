/**
 *
 */
package net.ripe.certification.validator.output;

import java.net.URI;

import net.ripe.certification.validator.fetchers.NotifyingCertificateRepositoryObjectFetcher;
import net.ripe.commons.certification.CertificateRepositoryObject;
import net.ripe.commons.certification.validation.ValidationCheck;
import net.ripe.commons.certification.validation.ValidationMessage;
import net.ripe.commons.certification.validation.ValidationResult;

import org.apache.log4j.Logger;

public class ObjectFetcherResultLogger implements NotifyingCertificateRepositoryObjectFetcher.FetchNotificationCallback {
    private static final Logger LOG = Logger.getLogger(ObjectFetcherResultLogger.class);
    private boolean logValidObjects;


    public ObjectFetcherResultLogger() {
    	logValidObjects = true;
    }

    public ObjectFetcherResultLogger(boolean logValidObjects) {
		this.logValidObjects = logValidObjects;
	}

	@Override
    public void afterFetchFailure(URI uri, ValidationResult result) {
        logResults(uri, result);
        LOG.info(uri + " is INVALID");
    }

    @Override
    public void afterFetchSuccess(URI uri, CertificateRepositoryObject object, ValidationResult result) {
        logResults(uri, result);
        if (logValidObjects) {
        	LOG.info(uri + " is VALID");
        }
    }

    @Override
    public void afterPrefetchFailure(URI uri, ValidationResult result) {
        logResults(uri, result);
    }

    @Override
    public void afterPrefetchSuccess(URI uri, ValidationResult result) {
        logResults(uri, result);
    }

    protected void logResults(URI uri, ValidationResult result) {
        for (ValidationCheck check: result.getResultsForCurrentLocation()) {
            String message = uri + ": " + ValidationMessage.getMessage(check);
            if (check.isOk()) {
            	if (logValidObjects ) {
            		LOG.debug("<OK> " + message);
            	}
            } else {
                LOG.error("<FAIL> " + message);
            }
        }
    }

}