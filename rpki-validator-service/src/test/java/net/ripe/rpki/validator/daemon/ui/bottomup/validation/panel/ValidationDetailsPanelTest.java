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
package net.ripe.rpki.validator.daemon.ui.bottomup.validation.panel;

import static org.junit.Assert.*;

import net.ripe.commons.certification.validation.ValidationLocation;
import net.ripe.commons.certification.validation.ValidationResult;
import net.ripe.rpki.validator.daemon.ui.AbstractWicketTest;

import org.apache.wicket.markup.html.panel.Panel;
import org.apache.wicket.util.tester.TestPanelSource;
import org.junit.Before;
import org.junit.Test;

public class ValidationDetailsPanelTest extends AbstractWicketTest {
    public ValidationResult validationResult;

    @Before
    public void setUpValidationResult() {
        validationResult = new ValidationResult();
        validationResult.setLocation(new ValidationLocation("objects.crl.valid"));
        validationResult.isTrue(true, "objects.crl.valid");
    }

    @Test
    public void shouldRender() {
        startPanel(validationResult);

        getTester().assertNoErrorMessage();
        getTester().assertNoInfoMessage();
    }

    @Test
    public void shouldDisplayLink() {
        startPanel(validationResult);

        getTester().executeAjaxEvent("panel:resultsLink", "onclick");

        String labelContents = getTester().getComponentFromLastRenderedPage("panel:resultsLink:linkLabel").getDefaultModelObjectAsString();
        assertEquals("hide validation details &raquo;", labelContents);

        getTester().assertNoErrorMessage();
        getTester().assertNoInfoMessage();
    }


    private void startPanel(final ValidationResult result) {
        getTester().startPanel(new TestPanelSource() {

            private static final long serialVersionUID = 1L;

            @Override
            public Panel getTestPanel(String panelId) {
                return new ValidationDetailsPanel(panelId, result);
            }
        });
    }
}
