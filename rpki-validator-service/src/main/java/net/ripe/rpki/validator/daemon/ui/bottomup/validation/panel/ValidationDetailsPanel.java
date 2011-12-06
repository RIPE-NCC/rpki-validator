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

import net.ripe.commons.certification.validation.ValidationCheck;
import net.ripe.commons.certification.validation.ValidationMessage;
import net.ripe.commons.certification.validation.ValidationResult;
import net.ripe.rpki.validator.daemon.ui.common.WicketUtil;
import org.apache.wicket.ajax.AjaxRequestTarget;
import org.apache.wicket.ajax.markup.html.AjaxLink;
import org.apache.wicket.markup.html.WebMarkupContainer;
import org.apache.wicket.markup.html.basic.Label;
import org.apache.wicket.markup.html.list.ListItem;
import org.apache.wicket.markup.html.list.ListView;
import org.apache.wicket.markup.html.panel.Panel;

import java.util.ArrayList;

public class ValidationDetailsPanel extends Panel {

    private static final long serialVersionUID = 1L;
    private static final String ID_LINK_LABEL = "linkLabel";

    public ValidationDetailsPanel(String id, ValidationResult result) {
        super(id);

        WebMarkupContainer wrapper = new WebMarkupContainer("listWrapper");
        wrapper.setOutputMarkupPlaceholderTag(true);
        wrapper.setVisible(false);
        add(wrapper);

        ListView<ValidationCheck> resultView = new ListView<ValidationCheck>("list", new ArrayList<ValidationCheck>(result.getAllValidationChecksForLocation(result.getCurrentLocation()))) {

            private static final long serialVersionUID = 1L;

            @Override
            protected void populateItem(ListItem<ValidationCheck> listItem) {
                final ValidationCheck validationCheck = listItem.getModelObject();
                String message = ValidationMessage.getMessage(validationCheck);
                listItem.add(WicketUtil.getStatusImage("checkmark", validationCheck.isOk()));
                listItem.add(new Label("step", message));
            }
        };

        wrapper.add(resultView);

        add(createDetailsLink(wrapper));
    }

    private AjaxLink<?> createDetailsLink(final WebMarkupContainer wrapper) {

        AjaxLink<?> resultsLink = new AjaxLink<Object>("resultsLink") {
            private static final long serialVersionUID = 1L;

            @Override
            public void onClick(AjaxRequestTarget target) {
                wrapper.setVisible(!wrapper.isVisible());
                target.addComponent(wrapper);

                Label label = createDetailsLabel(ID_LINK_LABEL, wrapper);
                addOrReplace(label);
                target.addComponent(label);

            }
        };

        Label showDetails = createDetailsLabel(ID_LINK_LABEL, wrapper);
        resultsLink.add(showDetails);
        return resultsLink;
    }

    private Label createDetailsLabel(String id, WebMarkupContainer wrapper) {
        Label label = new Label(id, wrapper.isVisible() ? "hide validation details &raquo;" : "show validation details &raquo;");
        label.setEscapeModelStrings(false);
        label.setOutputMarkupId(true);
        return label;
    }

}
