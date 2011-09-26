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
        LOG.warn("failed to prefetch " + uri);
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