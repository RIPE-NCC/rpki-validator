package net.ripe.certification.validator.fetchers;

import static org.easymock.EasyMock.*;
import static org.junit.Assert.*;

import java.net.URI;

import net.ripe.certification.validator.RepositoryObjectsSetUpHelper;
import net.ripe.commons.certification.CertificateRepositoryObject;
import net.ripe.commons.certification.cms.manifest.ManifestCms;
import net.ripe.commons.certification.crl.X509Crl;
import net.ripe.commons.certification.validation.CertificateRepositoryObjectValidationContextTest;
import net.ripe.commons.certification.validation.ValidationResult;
import net.ripe.commons.certification.validation.objectvalidators.CertificateRepositoryObjectValidationContext;
import net.ripe.utils.Specification;
import net.ripe.utils.Specifications;

import org.junit.Before;
import org.junit.Test;


public class NotifyingCertificateRepositoryObjectFetcherTest {

    private static final URI TEST_URI = URI.create("rsync://host/path/file.txt");
    private static final Specification<byte[]> FILE_CONTENT_SPECIFICATION = Specifications.alwaysTrue();

    private ValidationResult result;
    private CertificateRepositoryObjectValidationContext context;
    private CertificateRepositoryObjectFetcher fetcher;
    private NotifyingCertificateRepositoryObjectFetcher.FetchNotificationCallback firstCallback;
    private NotifyingCertificateRepositoryObjectFetcher.FetchNotificationCallback secondCallback;
    private NotifyingCertificateRepositoryObjectFetcher subject;
    private Object[] mocks;


    @Before
    public void setUp() {
        result = new ValidationResult();
        result.push(TEST_URI);

        context = CertificateRepositoryObjectValidationContextTest.create();
        fetcher = createMock(CertificateRepositoryObjectFetcher.class);
        firstCallback = createMock(NotifyingCertificateRepositoryObjectFetcher.FetchNotificationCallback.class);
        secondCallback = createMock(NotifyingCertificateRepositoryObjectFetcher.FetchNotificationCallback.class);
        mocks = new Object[] { fetcher, firstCallback, secondCallback };

        subject = new NotifyingCertificateRepositoryObjectFetcher(fetcher);
        subject.addCallback(firstCallback);
        subject.addCallback(secondCallback);
    }

    @Test
    public void shouldNotifyOnPrefetchSuccess() {
        result.isTrue(true, "dummy.check");
        fetcher.prefetch(TEST_URI, result);
        firstCallback.afterPrefetchSuccess(TEST_URI, result);
        secondCallback.afterPrefetchSuccess(TEST_URI, result);
        replay(mocks);

        subject.prefetch(TEST_URI, result);
        verify(mocks);
    }

    @Test
    public void shouldNotifyOnPrefetchFailure() {
        result.isTrue(false, "dummy.check");
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
        result.isTrue(true, "dummy.check");

        expect(fetcher.getObject(TEST_URI, context, FILE_CONTENT_SPECIFICATION, result)).andReturn(object);
        firstCallback.afterFetchSuccess(TEST_URI, object, result);
        secondCallback.afterFetchSuccess(TEST_URI, object, result);
        replay(mocks);

        assertSame(object, subject.getObject(TEST_URI, context, FILE_CONTENT_SPECIFICATION, result));

        verify(mocks);
    }

    @Test
    public void shouldNotifyOnGetObjectFailure() {
        result.isTrue(false, "dummy.check");

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
        result.isTrue(true, "dummy.check");

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
        result.isTrue(true, "dummy.check");

        expect(fetcher.getManifest(TEST_URI, context, result)).andReturn(object);
        firstCallback.afterFetchSuccess(TEST_URI, object, result);
        secondCallback.afterFetchSuccess(TEST_URI, object, result);
        replay(mocks);

        assertSame(object, subject.getManifest(TEST_URI, context, result));

        verify(mocks);
    }
}
