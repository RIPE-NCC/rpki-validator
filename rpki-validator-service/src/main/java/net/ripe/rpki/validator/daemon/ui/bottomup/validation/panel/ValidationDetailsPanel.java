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

        ListView<ValidationCheck> resultView = new ListView<ValidationCheck>("list", new ArrayList<ValidationCheck>(result.getResultsForCurrentLocation())) {

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
