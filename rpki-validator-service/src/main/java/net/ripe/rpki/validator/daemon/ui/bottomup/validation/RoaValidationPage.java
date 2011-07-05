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

import net.ripe.rpki.validator.daemon.service.BottomUpRoaValidationResult;
import net.ripe.rpki.validator.daemon.service.BottomUpRoaValidationService;
import net.ripe.rpki.validator.daemon.ui.bottomup.validation.panel.RoaInfoPanel;
import net.ripe.rpki.validator.daemon.ui.bottomup.validation.panel.RoaValidityPanel;
import net.ripe.rpki.validator.daemon.ui.bottomup.validation.panel.UploadPanel;
import net.ripe.rpki.validator.daemon.ui.bottomup.validation.panel.ValidationDetailsPanel;
import net.ripe.rpki.validator.daemon.ui.common.AbstractPage;
import net.ripe.rpki.validator.daemon.ui.common.NavigationalCallbackHandler;

import org.apache.wicket.markup.html.WebMarkupContainer;
import org.apache.wicket.markup.html.panel.EmptyPanel;
import org.apache.wicket.model.Model;
import org.apache.wicket.spring.injection.annot.SpringBean;

public class RoaValidationPage extends AbstractPage {

	private static final long serialVersionUID = 1l;

    static final String ID_ROA_INFO = "roaInfo";
    static final String ID_ROA_VALIDITY = "roaValidity";
    static final String ID_ROA_VALIDATION_DETAILS = "validationDetailsPanel";

    @SpringBean(name = "roaValidationService")
    private BottomUpRoaValidationService roaValidationService;


    public RoaValidationPage() {
        this(null);
    }

    RoaValidationPage(Model<byte[]> uploadContents) {
    	add(new UploadPanel("uploadPanel", new CallbackHandler()));

    	if (uploadContents != null) {
    		BottomUpRoaValidationResult result = roaValidationService.validateRoa(uploadContents.getObject());
    		add(createRoaValidityPanel(result));
    		add(createRoaInfoPanel(result));
    		add(createValidationDetailsPanel(result));
    	} else {
    		add(new EmptyPanel(ID_ROA_VALIDITY));
    		add(new EmptyPanel(ID_ROA_INFO));
    		add(new EmptyPanel(ID_ROA_VALIDATION_DETAILS));
    	}
    }

    private WebMarkupContainer createRoaValidityPanel(BottomUpRoaValidationResult result) {
		return new RoaValidityPanel(ID_ROA_VALIDITY, result);
	}

	private WebMarkupContainer createRoaInfoPanel(BottomUpRoaValidationResult result) {
        if (result.getRoa() != null) {
            return new RoaInfoPanel(ID_ROA_INFO, result);
        } else {
        	error("The uploaded file could not be parsed as a ROA");
            return new EmptyPanel(ID_ROA_INFO);
        }
    }

    private WebMarkupContainer createValidationDetailsPanel(BottomUpRoaValidationResult result) {
        final WebMarkupContainer validationPanel;

        if (isWithDetailedResults(result)) {
            validationPanel = new ValidationDetailsPanel(ID_ROA_VALIDATION_DETAILS, result.getResult());
        } else {
            validationPanel = new EmptyPanel(ID_ROA_VALIDATION_DETAILS);
        }
        return validationPanel;
    }

    private boolean isWithDetailedResults(BottomUpRoaValidationResult result) {
        return result.getResult() != null && result.getResult().getValidatedLocations() != null && result.getResult().getValidatedLocations().size() > 0;
    }

    /**
     * callback called on submit inside upload panel
     */
    private class CallbackHandler implements NavigationalCallbackHandler<byte[]> {
        private static final long serialVersionUID = 1l;

        @Override
        public void callback(byte[] fileContents) {
            Model<byte[]> fileContentsModel = new Model<byte[]>(fileContents);

            RoaValidationPage.this.setResponsePage(new RoaValidationPage(fileContentsModel));
        }
    }
}
