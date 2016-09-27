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
package net.ripe.rpki.validator.util;

import com.google.common.base.Charsets;
import com.google.common.base.Joiner;
import com.google.common.base.Objects;
import com.google.common.io.Files;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.Validate;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Properties;

/**
 * Represents a Trust Anchor Locator as defined in <a href="https://tools.ietf.org/html/rfc7730">RFC 7730</a>
 */
public class TrustAnchorLocator {

    private final File file;

    private final String caName;

    private final List<URI> certificateLocations;

    private final String publicKeyInfo;

    private final List<URI> prefetchUris;

    private URI fetchedCertificateUri;

    public static TrustAnchorLocator fromFile(File file) throws TrustAnchorExtractorException {
        try {
            String contents = Files.toString(file, Charsets.UTF_8);
            String trimmed = contents.trim();
            if (trimmed.startsWith("rsync://") || trimmed.startsWith("https://") || trimmed.startsWith("http://")) {
                return readStandardTrustAnchorLocator(file);
            } else {
                return readExtendedTrustAnchorLocator(file, contents);
            }
        } catch (IllegalArgumentException | URISyntaxException | IOException e) {
            throw new TrustAnchorExtractorException("failed to load trust anchor locator " + file + ": " + e.getMessage(), e);
        }
    }

    /**
     * @see <a href="https://tools.ietf.org/html/rfc7730">RFC 7730</a>
     */
    private static TrustAnchorLocator readStandardTrustAnchorLocator(File file) throws URISyntaxException, IOException {
        String caName = Files.getNameWithoutExtension(file.getName());

        final ArrayList<URI> certificateLocations = new ArrayList<>();

        try (final BufferedReader reader = Files.newReader(file, Charsets.UTF_8)) {
            String line;
            while ((line = reader.readLine()) != null) {
                final String trimmed = line.trim();
                if (looksLikeUri(trimmed)) {
                    certificateLocations.add(new URI(trimmed));
                } else break;
            }

            if (line == null)
                throw new IllegalArgumentException("publicKeyInfo not found in TAL file " + file.toString());

            StringBuilder publicKeyInfo = new StringBuilder(line.trim());
            while ((line = reader.readLine()) != null) {
                publicKeyInfo.append(line.trim());
            }
            return new TrustAnchorLocator(file, caName, certificateLocations, publicKeyInfo.toString(), Collections.<URI>emptyList());
        }
    }

    private static boolean looksLikeUri(String string) {
        return string.startsWith("rsync://") || string.startsWith("https://") || string.startsWith("http://");
    }

    private static TrustAnchorLocator readExtendedTrustAnchorLocator(File file, String contents) throws IOException, URISyntaxException {
        Properties p = new Properties();
        p.load(new StringReader(contents));

        String caName = p.getProperty("ca.name");
        String loc = p.getProperty("certificate.location");
        Validate.notEmpty(loc, "'certificate.location' must be provided");
        URI location = new URI(loc);
        String publicKeyInfo = p.getProperty("public.key.info", "").replaceAll("\\s+", "");
        String[] uris = p.getProperty("prefetch.uris", "").split(",");
        List<URI> prefetchUris = new ArrayList<URI>(uris.length);
        for (String uri : uris) {
            uri = uri.trim();
            if (StringUtils.isNotBlank(uri)) {
                if (!uri.endsWith("/") && uri.startsWith("rsync://")) {
                    uri += "/";
                }
                prefetchUris.add(new URI(uri));
            }
        }
        return new TrustAnchorLocator(file, caName, Collections.singletonList(location), publicKeyInfo, prefetchUris);
    }

    public TrustAnchorLocator(File file, String caName, List<URI> location, String publicKeyInfo, List<URI> prefetchUris) {
        Validate.notEmpty(caName, "'ca.name' must be provided");
        Validate.notNull(location, "'certificate.location' must be provided");
        Validate.notEmpty(publicKeyInfo, "'public.key.info' must be provided");
        this.file = file;
        this.caName = caName;
        this.certificateLocations = location;
        this.publicKeyInfo = publicKeyInfo;
        this.prefetchUris = prefetchUris;
    }

    public File getFile() {
        return file;
    }

    public String getCaName() {
        return caName;
    }

    public List<URI> getCertificateLocations() {
        return certificateLocations;
    }

    public String getPublicKeyInfo() {
        return publicKeyInfo;
    }

    public List<URI> getPrefetchUris() {
        return prefetchUris;
    }

    @Override
    public String toString() {
        return Objects.toStringHelper(this)
                      .add("caName", getCaName())
                      .add("certificationLocation", Joiner.on(", ").join(getCertificateLocations()))
                      .toString();
    }

    public URI getFetchedCertificateUri() {
        return fetchedCertificateUri;
    }

    public void setFetchedCertificateUri(URI fetchedCertificateUri) {
        this.fetchedCertificateUri = fetchedCertificateUri;
    }
}
