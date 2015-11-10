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
package net.ripe.rpki.validator.commands;

import net.ripe.rpki.commons.validation.ValidationResult;
import net.ripe.rpki.commons.validation.objectvalidators.CertificateRepositoryObjectValidationContext;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.util.List;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class BottomUpCertificateRepositoryObjectValidatorTest {

    private BottomUpCertificateRepositoryObjectValidator validator;

    @Before
    public void setUp() {
        validator = new BottomUpCertificateRepositoryObjectValidator(null, null, null);
    }

    @Test
    public void shouldCreateAndDeleteTempDirectory() {
        SingleObjectWalker singleObjectWalker = new SingleObjectWalker(null, null, null, null, null) {

            @Override
            public ValidationResult execute(List<CertificateRepositoryObjectValidationContext> trustAnchors) {
                // Do nothing for this test
                return ValidationResult.withLocation("n/a");
            }

        };
        validator.setSingleObjectWalker(singleObjectWalker);

        File tempDir = validator.getTempDirectory();
        assertTrue("Temp dir should exist: " + tempDir.getAbsolutePath(), tempDir.exists());
        assertTrue("Temp dir should be writable: " + tempDir.getAbsolutePath(), tempDir.canWrite());

        validator.validate();

        assertFalse("Temp dir should be removed: " + tempDir.getAbsolutePath(), tempDir.exists());
    }
}
