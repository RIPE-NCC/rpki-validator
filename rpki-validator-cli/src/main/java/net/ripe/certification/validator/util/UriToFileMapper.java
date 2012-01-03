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
        result.rejectIfFalse(RSYNC_SCHEME.equalsIgnoreCase(uri.getScheme()), VALIDATOR_URI_RSYNC_SCHEME, uri.toString());
        result.rejectIfNull(uri.getHost(), VALIDATOR_URI_HOST, uri.toString());
        result.rejectIfNull(uri.getRawPath(), VALIDATOR_URI_PATH, uri.toString());
        String s = uri.toString();
        result.rejectIfTrue(s.contains("/../") || s.endsWith("/.."), VALIDATOR_URI_SAFETY, uri.toString());
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
