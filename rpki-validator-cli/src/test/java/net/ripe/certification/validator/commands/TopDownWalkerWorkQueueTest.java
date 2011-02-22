package net.ripe.certification.validator.commands;

import static org.junit.Assert.*;

import java.net.URI;
import java.util.LinkedList;
import java.util.Queue;

import net.ripe.commons.certification.validation.CertificateRepositoryObjectValidationContextTest;
import net.ripe.commons.certification.validation.objectvalidators.CertificateRepositoryObjectValidationContext;
import net.ripe.commons.certification.x509cert.X509ResourceCertificate;
import net.ripe.commons.certification.x509cert.X509ResourceCertificateTest;
import net.ripe.ipresource.IpResourceSet;

import org.junit.Before;
import org.junit.Test;


public class TopDownWalkerWorkQueueTest {

    private CertificateRepositoryObjectValidationContext context = CertificateRepositoryObjectValidationContextTest.create();
    private Queue<CertificateRepositoryObjectValidationContext> queue;
    private TopDownWalkerWorkQueue subject;

    @Before
    public void setUp() {
        queue = new LinkedList<CertificateRepositoryObjectValidationContext>();
        subject = new TopDownWalkerWorkQueue(queue);
    }

    @Test
    public void shouldAddAndRemoveItemsToWorkQueue() {

        subject.add(context);

        assertFalse(subject.isEmpty());
        assertEquals(1, queue.size());
        assertTrue(queue.contains(context));

        assertEquals(context, subject.remove());
    }

    @Test
    public void shouldNotAddItemsPreviouslyAdded() {
        subject.add(context);
        subject.add(context);

        assertEquals(1, subject.size());

        subject.remove();
        subject.add(context);

        assertEquals(0, subject.size());
        assertTrue(subject.isEmpty());
    }

    @Test
    public void shouldDefaultToFirstInFirstOutQueue() {
        subject = new TopDownWalkerWorkQueue();
        X509ResourceCertificate anotherCertificate = X509ResourceCertificateTest.createSelfSignedCaResourceCertificate(IpResourceSet.parse("AS0-AS100"));
        CertificateRepositoryObjectValidationContext anotherContext = new CertificateRepositoryObjectValidationContext(URI.create("rsync://local/foo"), anotherCertificate);

        subject.add(context);
        subject.add(anotherContext);

        assertEquals(context, subject.remove());
        assertEquals(anotherContext, subject.remove());
    }
}
