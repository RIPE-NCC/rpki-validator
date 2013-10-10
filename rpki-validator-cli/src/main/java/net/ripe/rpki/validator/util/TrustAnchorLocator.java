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

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.Validate;

import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Properties;

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
        try {
            String contents = FileUtils.readFileToString(file, "UTF-8");
            if (contents.trim().startsWith("rsync://")) {
                return readStandardTrustAnchorLocator(file, contents);
            } else {
                return readExtendedTrustAnchorLocator(file, contents);
            }
        } catch (IllegalArgumentException e) {
            throw new TrustAnchorExtractorException("failed to load trust anchor locator " + file + ": " + e.getMessage(), e);
        } catch (IOException e) {
            throw new TrustAnchorExtractorException("failed to open trust anchor locator " + file + ": " + e.getMessage(), e);
        } catch (URISyntaxException e) {
            throw new TrustAnchorExtractorException("failed to load trust anchor locator " + file + ": " + e.getMessage(), e);
        }
    }

    /**
     * @see http://tools.ietf.org/html/draft-ietf-sidr-ta-07
     */
    private static TrustAnchorLocator readStandardTrustAnchorLocator(File file, String contents) throws URISyntaxException {
        String caName = FilenameUtils.getBaseName(file.getName());
        String[] lines = contents.trim().split("\\s*(\r\n|\n\r|\n|\r)\\s*");
        URI location = new URI(lines[0]);
        int i = 1;
        while (lines[i].startsWith("rsync://")) {
            i++;
        }
        String publicKeyInfo = StringUtils.join(Arrays.copyOfRange(lines, i, lines.length));
        return new TrustAnchorLocator(file, caName, location, publicKeyInfo, new ArrayList<URI>());
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
                if (!uri.endsWith("/")) {
                    uri += "/";
                }
                prefetchUris.add(new URI(uri));
            }
        }
        return new TrustAnchorLocator(file, caName, location, publicKeyInfo, prefetchUris);
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
