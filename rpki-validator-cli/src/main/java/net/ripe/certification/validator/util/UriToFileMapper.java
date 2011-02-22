package net.ripe.certification.validator.util;

import static net.ripe.commons.certification.validation.ValidationString.*;

import java.io.File;
import java.net.URI;

import net.ripe.commons.certification.validation.ValidationResult;

import org.apache.commons.lang.Validate;

public class UriToFileMapper {

    private static final String RSYNC_SCHEME = "rsync";

    private File targetDirectory;

    public UriToFileMapper(File targetDirectory) {
        Validate.notNull(targetDirectory);
        this.targetDirectory = targetDirectory;
    }

    public File map(URI uri, ValidationResult result) {
        Validate.notNull(result);
        Validate.notNull(uri);
        result.isTrue(RSYNC_SCHEME.equalsIgnoreCase(uri.getScheme()), VALIDATOR_URI_RSYNC_SCHEME, uri);
        result.notNull(uri.getHost(), VALIDATOR_URI_HOST, uri);
        result.notNull(uri.getRawPath(), VALIDATOR_URI_PATH, uri);
        String s = uri.toString();
        result.isFalse(s.contains("/../") || s.endsWith("/.."), VALIDATOR_URI_SAFETY, uri);
        if (result.hasFailureForCurrentLocation()) {
            return null;
        }
        return new File(new File(targetDirectory, getHostPortAsString(uri)), uri.getRawPath());
    }

    private String getHostPortAsString(URI uri) {
        String host = uri.getHost();
        int port = uri.getPort();
        return port == -1 ? host : (host + ":" + port);
    }
}
