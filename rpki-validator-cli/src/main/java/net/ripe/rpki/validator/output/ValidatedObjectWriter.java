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

import net.ripe.rpki.validator.fetchers.NotifyingCertificateRepositoryObjectFetcher.Listener;
import net.ripe.rpki.validator.util.UriToFileMapper;

import net.ripe.rpki.commons.crypto.CertificateRepositoryObject;
import net.ripe.rpki.commons.validation.ValidationResult;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang.Validate;
import org.apache.log4j.Logger;

import java.io.File;
import java.io.IOException;
import java.net.URI;

/**
 * Writes validated objects to the location as specified by the {@link UriToFileMapper}.
 */
public class ValidatedObjectWriter implements Listener {
    private static final Logger LOG = Logger.getLogger(ValidatedObjectWriter.class);

    private UriToFileMapper uriToFileMapper;

    public ValidatedObjectWriter(UriToFileMapper uriToFileMapper) {
        this.uriToFileMapper = uriToFileMapper;
    }

    @Override
    public void afterFetchFailure(URI uri, ValidationResult result) {
    }

    @Override
    public void afterFetchSuccess(URI uri, CertificateRepositoryObject object, ValidationResult result) {
        File destinationFile = uriToFileMapper.map(uri, result);
        Validate.notNull(destinationFile, "uri could not be mapped to file");
        try {
            if (destinationFile.exists()) {
                LOG.error("destination file '" + destinationFile.getAbsolutePath() + "' already exists, validated object not stored");
            } else {
                FileUtils.writeByteArrayToFile(destinationFile, object.getEncoded());
            }
        } catch (IOException e) {
            LOG.error("error writing validated object to file '" + destinationFile.getAbsolutePath() + "'");
        }
    }

    @Override
    public void afterPrefetchFailure(URI uri, ValidationResult result) {
    }

    @Override
    public void afterPrefetchSuccess(URI uri, ValidationResult result) {
    }

}
