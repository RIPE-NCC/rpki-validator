package net.ripe.certification.validator.fetchers;

import static org.easymock.EasyMock.*;
import static org.junit.Assert.*;

import java.net.URI;

import net.ripe.certification.validator.RepositoryObjectsSetUpHelper;
import net.ripe.commons.certification.cms.manifest.ManifestCms;
import net.ripe.commons.certification.crl.X509Crl;
import net.ripe.commons.certification.validation.CertificateRepositoryObjectValidationContextTest;
import net.ripe.commons.certification.validation.ValidationResult;
import net.ripe.commons.certification.validation.objectvalidators.CertificateRepositoryObjectValidationContext;
import net.ripe.commons.certification.x509cert.X509ResourceCertificate;
import net.ripe.utils.Specification;
import net.ripe.utils.Specifications;

import org.junit.Before;
import org.junit.Test;


public class CachingCertificateRepositoryObjectFetcherTest {

    private URI uri;
    private CertificateRepositoryObjectValidationContext context;
    private Specification<byte[]> fileContentSpecification;
    private ValidationResult result;
    private CertificateRepositoryObjectFetcher fetcher;
    private CachingCertificateRepositoryObjectFetcher subject;

    @Before
    public void setUp() {
        uri = URI.create("rsync://host/path/");
        context = CertificateRepositoryObjectValidationContextTest.create();
        fileContentSpecification = Specifications.alwaysTrue();
        result = new ValidationResult();
        result.push(uri);
        fetcher = createMock(CertificateRepositoryObjectFetcher.class);
        subject = new CachingCertificateRepositoryObjectFetcher(fetcher);
    }

    @Test
    public void shouldPassOnPrefetch() {
        fetcher.prefetch(uri, result); expectLastCall().times(2);
        replay(fetcher);

        subject.prefetch(uri, result);
        subject.prefetch(uri, result);

        verify(fetcher);
    }

    @Test
    public void shouldCacheSuccessFromGetObject() {
        X509ResourceCertificate object = RepositoryObjectsSetUpHelper.getChildResourceCertificate();
        expect(fetcher.getObject(uri, context, fileContentSpecification, result)).andReturn(object).once();
        replay(fetcher);

        assertEquals(object, subject.getObject(uri, context, fileContentSpecification, result));
        assertEquals(object, subject.getObject(uri, context, fileContentSpecification, result));

        verify(fetcher);
    }

    @Test
    public void shouldCacheFailureFromGetObject() {
        expect(fetcher.getObject(uri, context, fileContentSpecification, result)).andReturn(null).once();
        replay(fetcher);

        assertEquals(null, subject.getObject(uri, context, fileContentSpecification, result));
        assertEquals(null, subject.getObject(uri, context, fileContentSpecification, result));
        assertEquals(null, subject.getCrl(uri, context, result));
        assertEquals(null, subject.getManifest(uri, context, result));

        verify(fetcher);
    }

    @Test
    public void shouldCacheManifestFromGetObject() {
        ManifestCms object = RepositoryObjectsSetUpHelper.getRootManifestCms();
        expect(fetcher.getObject(uri, context, fileContentSpecification, result)).andReturn(object).once();
        replay(fetcher);

        assertEquals(object, subject.getObject(uri, context, fileContentSpecification, result));
        assertEquals(object, subject.getManifest(uri, context, result));
        assertNull(subject.getCrl(uri, context, result));

        verify(fetcher);
    }

    @Test
    public void shouldCacheFailureFromGetManifest() {
        expect(fetcher.getManifest(uri, context, result)).andReturn(null).once();
        replay(fetcher);

        assertEquals(null, subject.getManifest(uri, context, result));
        assertEquals(null, subject.getManifest(uri, context, result));
        assertEquals(null, subject.getObject(uri, context, fileContentSpecification, result));

        verify(fetcher);
    }

    @Test
    public void shouldCacheSuccessFromGetManifest() {
        ManifestCms object = RepositoryObjectsSetUpHelper.getRootManifestCms();
        expect(fetcher.getManifest(uri, context, result)).andReturn(object).once();
        replay(fetcher);

        assertEquals(object, subject.getManifest(uri, context, result));
        assertEquals(object, subject.getManifest(uri, context, result));
        assertEquals(object, subject.getObject(uri, context, fileContentSpecification, result));

        verify(fetcher);
    }

    @Test
    public void shouldCacheSuccessFromGetCrl() {
        X509Crl object = RepositoryObjectsSetUpHelper.getRootCrl();
        expect(fetcher.getCrl(uri, context, result)).andReturn(object).once();
        replay(fetcher);

        assertEquals(object, subject.getCrl(uri, context, result));
        assertEquals(object, subject.getCrl(uri, context, result));
        assertEquals(object, subject.getObject(uri, context, fileContentSpecification, result));

        verify(fetcher);
    }

    @Test
    public void shouldCacheFailureFromGetCrl() {
        expect(fetcher.getCrl(uri, context, result)).andReturn(null).once();
        replay(fetcher);

        assertEquals(null, subject.getCrl(uri, context, result));
        assertEquals(null, subject.getCrl(uri, context, result));
        assertEquals(null, subject.getObject(uri, context, fileContentSpecification, result));

        verify(fetcher);
    }

    @Test
    public void shouldCacheCrlFromGetObject() {
        X509Crl object = RepositoryObjectsSetUpHelper.getRootCrl();
        expect(fetcher.getObject(uri, context, fileContentSpecification, result)).andReturn(object).once();
        replay(fetcher);

        assertEquals(object, subject.getObject(uri, context, fileContentSpecification, result));
        assertEquals(object, subject.getCrl(uri, context, result));
        assertNull(subject.getManifest(uri, context, result));

        verify(fetcher);
    }

}
