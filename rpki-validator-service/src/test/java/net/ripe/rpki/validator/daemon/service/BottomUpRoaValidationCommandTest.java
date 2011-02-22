package net.ripe.rpki.validator.daemon.service;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.File;
import java.util.List;

import net.ripe.commons.certification.validation.objectvalidators.CertificateRepositoryObjectValidationContext;

import org.junit.Test;

public class BottomUpRoaValidationCommandTest {

    private BottomUpRoaValidationCommand subject = new BottomUpRoaValidationCommand();
    
    @Test
    public void shouldReadTrustAnchor() {
        List<CertificateRepositoryObjectValidationContext> trustAnchors = subject.getTrustAnchors(new File("./config/root.tal"));
        assertEquals(1, trustAnchors.size());
        CertificateRepositoryObjectValidationContext ta = trustAnchors.get(0);
        assertNotNull(ta);
    }
    
}
