package net.ripe.certification.validator.commands;

import java.util.HashSet;
import java.util.LinkedList;
import java.util.Queue;
import java.util.Set;

import net.ripe.commons.certification.validation.objectvalidators.CertificateRepositoryObjectValidationContext;
import net.ripe.commons.certification.x509cert.X509ResourceCertificate;

import org.apache.commons.lang.Validate;

/**
 * A queue that keeps track of all certificates ever added and never allows the same certificate to be added twice.
 */
public class TopDownWalkerWorkQueue {

    private final Set<X509ResourceCertificate> added;
    private final Queue<CertificateRepositoryObjectValidationContext> queue;

    public TopDownWalkerWorkQueue() {
        this(new LinkedList<CertificateRepositoryObjectValidationContext>());
    }

    public TopDownWalkerWorkQueue(Queue<CertificateRepositoryObjectValidationContext> queue) {
        this.added = new HashSet<X509ResourceCertificate>();
        this.queue = queue;
    }

    public void add(CertificateRepositoryObjectValidationContext context) {
    	Validate.isTrue(context.getCertificate() instanceof X509ResourceCertificate, "Top down walker can only handle resource certs");
        if (added.add((X509ResourceCertificate) context.getCertificate())) {
            queue.add(context);
        }
    }

    public CertificateRepositoryObjectValidationContext remove() {
        return queue.remove();
    }

    public boolean isEmpty() {
        return queue.isEmpty();
    }

    public int size() {
        return queue.size();
    }

}
