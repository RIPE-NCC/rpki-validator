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
package net.ripe.rpki.validator.daemon.service;

import net.ripe.commons.certification.cms.manifest.ManifestCms;
import net.ripe.commons.certification.cms.manifest.ManifestCmsTest;
import net.ripe.commons.certification.cms.roa.RoaCms;
import net.ripe.commons.certification.cms.roa.RoaCmsObjectMother;
import net.ripe.commons.certification.validation.ValidationResult;
import org.junit.Before;
import org.junit.Test;

import java.io.File;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;


public class BottomUpRoaValidationServiceTest {

    private BottomUpRoaValidationServiceImpl subject;
    private StubbedBottomUpRoaValidationCommand stubbedBottomUpRoaValidationCommand;

    @Before
    @SuppressWarnings("deprecation")
    public void setUp() {
        subject = new BottomUpRoaValidationServiceImpl();
        stubbedBottomUpRoaValidationCommand = new StubbedBottomUpRoaValidationCommand();
        subject.setValidationCommand(stubbedBottomUpRoaValidationCommand);
        subject.setTalLocation("./config/root.tal");
    }

    @Test
    public void shouldRejectGarbageUploaded() {
        byte[] garbage = new byte[]{0x10, 0x12, 0x3};
        BottomUpRoaValidationResult result = subject.validateRoa(garbage);
        assertFalse(result.isValid());
        assertFalse(stubbedBottomUpRoaValidationCommand.isCalled());
    }

    @Test
    public void shouldRejectOtherRpkiObjects() {
        ManifestCms manifestObject = ManifestCmsTest.getRootManifestCms();
        byte[] encodedManifestObject = manifestObject.getEncoded();
        BottomUpRoaValidationResult result = subject.validateRoa(encodedManifestObject);
        assertFalse(result.isValid());
        assertFalse(stubbedBottomUpRoaValidationCommand.isCalled());
    }

    @Test
    public void shouldValidateRoa() {
        RoaCms roaCms = RoaCmsObjectMother.getRoaCms();
        subject.validateRoa(roaCms.getEncoded());
        assertTrue(stubbedBottomUpRoaValidationCommand.isCalled());
    }

    private class StubbedBottomUpRoaValidationCommand extends BottomUpRoaValidationCommand {

        private boolean called = false;

        @Override
        public ValidationResult validate(RoaCms roaCms, File talFile) {
            called = true;
            return new ValidationResult();
        }

        public boolean isCalled() {
            return called;
        }

    }


}
