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
package net.ripe.rpki.validator.daemon.ui.bottomup.validation;

import static org.junit.Assert.*;

import static org.easymock.EasyMock.*;

import net.ripe.commons.certification.cms.roa.RoaCmsObjectMother;
import net.ripe.commons.certification.validation.ValidationResult;
import net.ripe.rpki.validator.daemon.service.BottomUpRoaValidationResult;
import net.ripe.rpki.validator.daemon.service.BottomUpRoaValidationService;
import net.ripe.rpki.validator.daemon.ui.AbstractWicketTest;

import org.apache.wicket.model.Model;
import org.junit.Before;
import org.junit.Test;

public class RoaValidationPageTest extends AbstractWicketTest {

    private BottomUpRoaValidationService service;

    @Before
    public void setUp() {
        service = createMock(BottomUpRoaValidationService.class);
        getMockContext().putBean("roaValidationService", service);
    }

    @Test
    public void shouldRender() {
        getTester().startPage(RoaValidationPage.class);

        getTester().assertNoErrorMessage();
        getTester().assertNoInfoMessage();
        getTester().assertRenderedPage(RoaValidationPage.class);
    }

    @Test
    public void shouldRenderForInvalidRoa() {
        byte[] contents = {0};

        expect(service.validateRoa(contents)).andReturn(new BottomUpRoaValidationResult());

        replay(service);

        getTester().startPage(new RoaValidationPage(new Model<byte[]>(contents)));

        getTester().assertNoErrorMessage();
        getTester().assertNoInfoMessage();
        getTester().assertRenderedPage(RoaValidationPage.class);

        String validity = getTester().getComponentFromLastRenderedPage(RoaValidationPage.ID_ROA_VALIDITY+":validity").getDefaultModelObjectAsString();
        assertEquals("invalid", validity);

        verify(service);
    }


    @Test
    public void shouldRenderForValidRoa() {
        byte[] contents = {0};

        BottomUpRoaValidationResult result = new BottomUpRoaValidationResult(RoaCmsObjectMother.getRoaCms(), new ValidationResult());
        expect(service.validateRoa(contents)).andReturn(result);

        replay(service);

        getTester().startPage(new RoaValidationPage(new Model<byte[]>(contents)));

        getTester().assertNoErrorMessage();
        getTester().assertNoInfoMessage();
        getTester().assertRenderedPage(RoaValidationPage.class);

        String validity = getTester().getComponentFromLastRenderedPage(RoaValidationPage.ID_ROA_VALIDITY+":validity").getDefaultModelObjectAsString();
        assertEquals("valid", validity);

        verify(service);
    }


}
