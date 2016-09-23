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
import org.junit.Test;

import java.io.File;
import java.net.URI;
import java.util.Collection;
import java.util.Collections;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;


public class TrustAnchorLocatorTest {

    private static final String EXPECTED_PUBLIC_KEY_INFO = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAovWQL2lh6knDx"
            + "GUG5hbtCXvvh4AOzjhDkSHlj22gn/1oiM9IeDATIwP44vhQ6L/xvuk7W6Kfa5ygmqQ+xOZOwTWPcrUbqaQyPNxokuivzyvqVZVDecOEqs78q58mSp9"
            + "nbtxmLRW7B67SJCBSzfa5XpVyXYEgYAjkk3fpmefU+AcxtxvvHB5OVPIaBfPcs80ICMgHQX+fphvute9XLxjfJKJWkhZqZ0v7pZm2uhkcPx1PMGcrG"
            + "ee0WSDC3fr3erLueagpiLsFjwwpX6F+Ms8vqz45H+DKmYKvPSstZjCCq9aJ0qANT9OtnfSDOS+aLRPjZryCNyvvBHxZXqj5YCGKtwIDAQAB";

    @Test
    public void should_load_release_trust_anchor_locator_files() {
        Collection<File> tals = FileUtils.listFiles(new File("../rpki-validator-app/conf/tal"), new String[] {"tal"}, false);
        for (File file : tals) {
            TrustAnchorLocator.fromFile(file);
        }
    }

    @Test
    public void should_load_standard_trust_anchor_locator_files() {
        TrustAnchorLocator tal = TrustAnchorLocator.fromFile(new File("src/test/resources/rpki-standard-tal.tal"));
        assertEquals("rpki-standard-tal", tal.getCaName());
        assertEquals(1, tal.getCertificateLocations().size());
        assertEquals(URI.create("rsync://rpki.example.org/rpki/hedgehog/root.cer"), tal.getCertificateLocations().get(0));
        assertEquals(EXPECTED_PUBLIC_KEY_INFO, tal.getPublicKeyInfo());
        assertEquals(Collections.EMPTY_LIST, tal.getPrefetchUris());
    }

    @Test
    public void should_load_standard_trust_anchor_locator_file_with_multi_locations() {
        TrustAnchorLocator tal = TrustAnchorLocator.fromFile(new File("src/test/resources/rpki-standard-tal-multi-location.tal"));
        assertEquals("rpki-standard-tal-multi-location", tal.getCaName());
        assertEquals(2, tal.getCertificateLocations().size());
        assertEquals(URI.create("http://pub-server.elasticbeanstalk.com/ta/local-test-ta.cer"), tal.getCertificateLocations().get(0));
        assertEquals(URI.create("rsync://rpki.example.org/rpki/hedgehog/root.cer"), tal.getCertificateLocations().get(1));
        assertEquals(EXPECTED_PUBLIC_KEY_INFO, tal.getPublicKeyInfo());
        assertTrue(tal.getPrefetchUris().isEmpty());
    }

    @Test
    public void should_load_extended_trust_anchor_locator_files() {
        TrustAnchorLocator tal1 = TrustAnchorLocator.fromFile(new File("src/test/resources/rpki-extended-tal1.tal"));
        assertEquals("TEST1 TAL", tal1.getCaName());
        assertEquals(1, tal1.getCertificateLocations().size());
        assertEquals(URI.create("rsync://foo.net.invald/root1.cer"), tal1.getCertificateLocations().get(0));
        assertEquals(EXPECTED_PUBLIC_KEY_INFO, tal1.getPublicKeyInfo());
        assertEquals(Collections.EMPTY_LIST, tal1.getPrefetchUris());

        TrustAnchorLocator tal2 = TrustAnchorLocator.fromFile(new File("src/test/resources/rpki-extended-tal2.tal"));
        assertEquals("TEST2 TAL", tal2.getCaName());
        assertEquals(1, tal2.getCertificateLocations().size());
        assertEquals(URI.create("rsync://foo.net.invald/root2.cer"), tal2.getCertificateLocations().get(0));
        assertEquals(EXPECTED_PUBLIC_KEY_INFO, tal2.getPublicKeyInfo());
        assertEquals(Collections.singletonList(URI.create("rsync://foo.net.invalid/")), tal2.getPrefetchUris());
    }

}
