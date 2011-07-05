/**
 * The BSD License
 *
 * Copyright (c) 2010, 2011 RIPE NCC
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
