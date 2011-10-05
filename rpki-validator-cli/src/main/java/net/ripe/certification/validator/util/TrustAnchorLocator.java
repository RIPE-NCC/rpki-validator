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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.Validate;

/**
 * Represents a Trust Anchor Locator as defined <a href="http://tools.ietf.org/html/draft-ietf-sidr-ta-07">here</a>
 */
public class TrustAnchorLocator {

    private final File file;

    private final String caName;

    private final URI certificateLocation;

    private final String publicKeyInfo;

    private final List<URI> prefetchUris;

    public static TrustAnchorLocator fromFile(File file) throws TrustAnchorExtractorException {
        FileInputStream input = null;
        try {
            Properties p = new Properties();
            input = FileUtils.openInputStream(file);
            p.load(input);

            String caName = p.getProperty("ca.name");
            String loc = p.getProperty("certificate.location");
            Validate.notEmpty(loc, "'certificate.location' must be provided");
            URI location = new URI(loc);
            String publicKeyInfo = p.getProperty("public.key.info");
            String[] uris = p.getProperty("prefetch.uris", "").split(",");
            List<URI> prefetchUris = new ArrayList<URI>(uris.length);
            for (String uri : uris) {
                uri = uri.trim();
                if (StringUtils.isNotBlank(uri)) {
                    if (!uri.endsWith("/")) {
                        uri += "/";
                    }
                    prefetchUris.add(new URI(uri));
                }
            }
            return new TrustAnchorLocator(file, caName, location, publicKeyInfo, prefetchUris);
        } catch (IllegalArgumentException e) {
            throw new TrustAnchorExtractorException("failed to load trust anchor locator " + file + ": " + e.getMessage(), e);
        } catch (IOException e) {
            throw new TrustAnchorExtractorException("failed to open trust anchor locator " + file + ": " + e.getMessage(), e);
        } catch (URISyntaxException e) {
            throw new TrustAnchorExtractorException("failed to load trust anchor locator " + file + ": " + e.getMessage(), e);
        } finally {
            IOUtils.closeQuietly(input);
        }
    }

    public TrustAnchorLocator(File file, String caName, URI location, String publicKeyInfo, List<URI> prefetchUris) {
        Validate.notEmpty(caName, "'ca.name' must be provided");
        Validate.notNull(location, "'certificate.location' must be provided");
        Validate.notEmpty(publicKeyInfo, "'public.key.info' must be provided");
        this.file = file;
        this.caName = caName;
        this.certificateLocation = location;
        this.publicKeyInfo = publicKeyInfo;
        this.prefetchUris = prefetchUris;
    }

    public File getFile() {
        return file;
    }

    public String getCaName() {
        return caName;
    }

    public URI getCertificateLocation() {
        return certificateLocation;
    }

    public String getPublicKeyInfo() {
        return publicKeyInfo;
    }

    public List<URI> getPrefetchUris() {
        return prefetchUris;
    }

}
