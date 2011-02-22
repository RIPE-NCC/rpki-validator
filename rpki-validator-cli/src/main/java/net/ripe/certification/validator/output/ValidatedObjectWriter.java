package net.ripe.certification.validator.output;

import java.io.File;
import java.io.IOException;
import java.net.URI;

import net.ripe.certification.validator.fetchers.NotifyingCertificateRepositoryObjectFetcher.FetchNotificationCallback;
import net.ripe.certification.validator.util.UriToFileMapper;
import net.ripe.commons.certification.CertificateRepositoryObject;
import net.ripe.commons.certification.validation.ValidationResult;

import org.apache.commons.io.FileUtils;
import org.apache.commons.lang.Validate;
import org.apache.log4j.Logger;

/**
 * Writes validated objects to the location as specified by the {@link UriToFileMapper}.
 */
public class ValidatedObjectWriter implements FetchNotificationCallback {
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
