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
package net.ripe.rpki.validator.fetchers;

import static org.junit.Assert.*;
import static org.mockito.Mockito.*;
import java.net.URI;
import net.ripe.rpki.commons.crypto.CertificateRepositoryObject;
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCms;
import net.ripe.rpki.commons.crypto.crl.X509Crl;
import net.ripe.rpki.commons.util.Specification;
import net.ripe.rpki.commons.util.Specifications;
import net.ripe.rpki.commons.validation.CertificateRepositoryObjectValidationContextTest;
import net.ripe.rpki.commons.validation.ValidationLocation;
import net.ripe.rpki.commons.validation.ValidationResult;
import net.ripe.rpki.commons.validation.objectvalidators.CertificateRepositoryObjectValidationContext;
import net.ripe.rpki.validator.RepositoryObjectsSetUpHelper;
import org.junit.Before;
import org.junit.Test;


public class NotifyingCertificateRepositoryObjectFetcherTest {

    private static final URI TEST_URI = URI.create("rsync://host/path/file.txt");
    private static final Specification<byte[]> FILE_CONTENT_SPECIFICATION = Specifications.alwaysTrue();

    private ValidationResult result;
    private CertificateRepositoryObjectValidationContext context;
    private CertificateRepositoryObjectFetcher fetcher;
    private NotifyingCertificateRepositoryObjectFetcher.Listener firstCallback;
    private NotifyingCertificateRepositoryObjectFetcher.Listener secondCallback;
    private NotifyingCertificateRepositoryObjectFetcher subject;


    @Before
    public void setUp() {
        result = ValidationResult.withLocation("unknown.cer");
        result.setLocation(new ValidationLocation(TEST_URI));

        context = CertificateRepositoryObjectValidationContextTest.create();
        fetcher = mock(CertificateRepositoryObjectFetcher.class);
        firstCallback = mock(NotifyingCertificateRepositoryObjectFetcher.Listener.class);
        secondCallback = mock(NotifyingCertificateRepositoryObjectFetcher.Listener.class);

        subject = new NotifyingCertificateRepositoryObjectFetcher(fetcher);
        subject.addCallback(firstCallback);
        subject.addCallback(secondCallback);
    }

    @Test
    public void shouldNotifyOnPrefetchSuccess() {
        result.rejectIfFalse(true, "dummy.check");

        subject.prefetch(TEST_URI, result);

        verify(fetcher).prefetch(TEST_URI, result);
        verify(firstCallback).afterPrefetchSuccess(TEST_URI, result);
        verify(secondCallback).afterPrefetchSuccess(TEST_URI, result);
        verify(firstCallback, never()).afterPrefetchFailure(TEST_URI, result);
        verify(secondCallback, never()).afterPrefetchFailure(TEST_URI, result);
    }

    @Test
    public void shouldNotifyOnPrefetchFailure() {
        result.rejectIfFalse(false, "dummy.check");

        subject.prefetch(TEST_URI, result);

        verify(fetcher).prefetch(TEST_URI, result);
        verify(firstCallback, never()).afterPrefetchSuccess(TEST_URI, result);
        verify(secondCallback, never()).afterPrefetchSuccess(TEST_URI, result);
        verify(firstCallback).afterPrefetchFailure(TEST_URI, result);
        verify(secondCallback).afterPrefetchFailure(TEST_URI, result);
    }

    @Test
    public void shouldNotifyOnGetObjectSuccess() {
        result.rejectIfFalse(true, "dummy.check");
        CertificateRepositoryObject object = RepositoryObjectsSetUpHelper.getRootResourceCertificate();
        when(fetcher.getObject(TEST_URI, context, FILE_CONTENT_SPECIFICATION, result)).thenReturn(object);

        assertSame(object, subject.getObject(TEST_URI, context, FILE_CONTENT_SPECIFICATION, result));

        verifyActionsAfterFetchingObjectWithoutValidationErrors(object);
    }

    @Test
    public void shouldNotifyOnGetObjectFailure() {
        result.rejectIfFalse(false, "dummy.check");
        when(fetcher.getObject(TEST_URI, context, FILE_CONTENT_SPECIFICATION, result)).thenReturn(null);

        assertNull(subject.getObject(TEST_URI, context, FILE_CONTENT_SPECIFICATION, result));

        verifyActionsAfterFetchingObjectWithValidationErrors();
    }

    @Test
    public void shouldNotifyOnGetCrl() {
        result.rejectIfFalse(true, "dummy.check");
        X509Crl object = RepositoryObjectsSetUpHelper.getRootCrl();
        when(fetcher.getCrl(TEST_URI, context, result)).thenReturn(object);

        assertSame(object, subject.getCrl(TEST_URI, context, result));

        verifyActionsAfterFetchingObjectWithoutValidationErrors(object);
    }

    @Test
    public void shouldNotifyOnGetManifest() {
        result.rejectIfFalse(true, "dummy.check");
        ManifestCms object = RepositoryObjectsSetUpHelper.getRootManifestCms();
        when(fetcher.getManifest(TEST_URI, context, result)).thenReturn(object);

        assertSame(object, subject.getManifest(TEST_URI, context, result));

        verifyActionsAfterFetchingObjectWithoutValidationErrors(object);
    }

    private void verifyActionsAfterFetchingObjectWithoutValidationErrors(CertificateRepositoryObject object) {
        verify(firstCallback).afterFetchSuccess(TEST_URI, object, result);
        verify(secondCallback).afterFetchSuccess(TEST_URI, object, result);
        verify(firstCallback, never()).afterFetchFailure(any(URI.class), any(ValidationResult.class));
        verify(secondCallback, never()).afterFetchFailure(any(URI.class), any(ValidationResult.class));
    }

    private void verifyActionsAfterFetchingObjectWithValidationErrors() {
        verify(firstCallback, never()).afterFetchSuccess(any(URI.class), any(CertificateRepositoryObject.class), any((ValidationResult.class)));
        verify(secondCallback, never()).afterFetchSuccess(any(URI.class), any(CertificateRepositoryObject.class), any((ValidationResult.class)));
        verify(firstCallback).afterFetchFailure(TEST_URI, result);
        verify(secondCallback).afterFetchFailure(TEST_URI, result);
    }
}
