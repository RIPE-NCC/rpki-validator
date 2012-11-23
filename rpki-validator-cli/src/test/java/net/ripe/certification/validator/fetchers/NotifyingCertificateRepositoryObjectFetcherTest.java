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
package net.ripe.certification.validator.fetchers;

import net.ripe.certification.validator.RepositoryObjectsSetUpHelper;
import net.ripe.rpki.commons.crypto.CertificateRepositoryObject;
import net.ripe.rpki.commons.crypto.cms.manifest.ManifestCms;
import net.ripe.rpki.commons.crypto.crl.X509Crl;
import net.ripe.rpki.commons.util.Specification;
import net.ripe.rpki.commons.util.Specifications;
import net.ripe.rpki.commons.validation.CertificateRepositoryObjectValidationContextTest;
import net.ripe.rpki.commons.validation.ValidationLocation;
import net.ripe.rpki.commons.validation.ValidationResult;
import net.ripe.rpki.commons.validation.objectvalidators.CertificateRepositoryObjectValidationContext;
import org.junit.Before;
import org.junit.Test;

import java.net.URI;

import static org.easymock.EasyMock.*;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;


public class NotifyingCertificateRepositoryObjectFetcherTest {

    private static final URI TEST_URI = URI.create("rsync://host/path/file.txt");
    private static final Specification<byte[]> FILE_CONTENT_SPECIFICATION = Specifications.alwaysTrue();

    private ValidationResult result;
    private CertificateRepositoryObjectValidationContext context;
    private CertificateRepositoryObjectFetcher fetcher;
    private NotifyingCertificateRepositoryObjectFetcher.Listener firstCallback;
    private NotifyingCertificateRepositoryObjectFetcher.Listener secondCallback;
    private NotifyingCertificateRepositoryObjectFetcher subject;
    private Object[] mocks;


    @Before
    public void setUp() {
        result = new ValidationResult();
        result.setLocation(new ValidationLocation(TEST_URI));

        context = CertificateRepositoryObjectValidationContextTest.create();
        fetcher = createMock(CertificateRepositoryObjectFetcher.class);
        firstCallback = createMock(NotifyingCertificateRepositoryObjectFetcher.Listener.class);
        secondCallback = createMock(NotifyingCertificateRepositoryObjectFetcher.Listener.class);
        mocks = new Object[] { fetcher, firstCallback, secondCallback };

        subject = new NotifyingCertificateRepositoryObjectFetcher(fetcher);
        subject.addCallback(firstCallback);
        subject.addCallback(secondCallback);
    }

    @Test
    public void shouldNotifyOnPrefetchSuccess() {
        result.rejectIfFalse(true, "dummy.check");
        fetcher.prefetch(TEST_URI, result);
        firstCallback.afterPrefetchSuccess(TEST_URI, result);
        secondCallback.afterPrefetchSuccess(TEST_URI, result);
        replay(mocks);

        subject.prefetch(TEST_URI, result);
        verify(mocks);
    }

    @Test
    public void shouldNotifyOnPrefetchFailure() {
        result.rejectIfFalse(false, "dummy.check");
        fetcher.prefetch(TEST_URI, result);
        firstCallback.afterPrefetchFailure(TEST_URI, result);
        secondCallback.afterPrefetchFailure(TEST_URI, result);
        replay(mocks);

        subject.prefetch(TEST_URI, result);
        verify(mocks);
    }

    @Test
    public void shouldNotifyOnGetObjectSuccess() {
        CertificateRepositoryObject object = RepositoryObjectsSetUpHelper.getRootResourceCertificate();
        result.rejectIfFalse(true, "dummy.check");

        expect(fetcher.getObject(TEST_URI, context, FILE_CONTENT_SPECIFICATION, result)).andReturn(object);
        firstCallback.afterFetchSuccess(TEST_URI, object, result);
        secondCallback.afterFetchSuccess(TEST_URI, object, result);
        replay(mocks);

        assertSame(object, subject.getObject(TEST_URI, context, FILE_CONTENT_SPECIFICATION, result));

        verify(mocks);
    }

    @Test
    public void shouldNotifyOnGetObjectFailure() {
        result.rejectIfFalse(false, "dummy.check");

        expect(fetcher.getObject(TEST_URI, context, FILE_CONTENT_SPECIFICATION, result)).andReturn(null);
        firstCallback.afterFetchFailure(TEST_URI, result);
        secondCallback.afterFetchFailure(TEST_URI, result);
        replay(mocks);

        assertNull(subject.getObject(TEST_URI, context, FILE_CONTENT_SPECIFICATION, result));

        verify(mocks);
    }

    @Test
    public void shouldNotifyOnGetCrl() {
        X509Crl object = RepositoryObjectsSetUpHelper.getRootCrl();
        result.rejectIfFalse(true, "dummy.check");

        expect(fetcher.getCrl(TEST_URI, context, result)).andReturn(object);
        firstCallback.afterFetchSuccess(TEST_URI, object, result);
        secondCallback.afterFetchSuccess(TEST_URI, object, result);
        replay(mocks);

        assertSame(object, subject.getCrl(TEST_URI, context, result));

        verify(mocks);
    }

    @Test
    public void shouldNotifyOnGetManifest() {
        ManifestCms object = RepositoryObjectsSetUpHelper.getRootManifestCms();
        result.rejectIfFalse(true, "dummy.check");

        expect(fetcher.getManifest(TEST_URI, context, result)).andReturn(object);
        firstCallback.afterFetchSuccess(TEST_URI, object, result);
        secondCallback.afterFetchSuccess(TEST_URI, object, result);
        replay(mocks);

        assertSame(object, subject.getManifest(TEST_URI, context, result));

        verify(mocks);
    }
}
