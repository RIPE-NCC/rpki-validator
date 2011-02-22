package net.ripe.rpki.validator.daemon.ui.verification;

import net.ripe.rpki.validator.daemon.service.BottomUpRoaValidationResult;
import net.ripe.rpki.validator.daemon.service.BottomUpRoaValidationService;
import net.ripe.rpki.validator.daemon.ui.common.AbstractPage;
import net.ripe.rpki.validator.daemon.ui.common.WicketUtil;
import net.ripe.rpki.validator.daemon.ui.verification.panel.RoaInfoPanel;
import net.ripe.rpki.validator.daemon.ui.verification.panel.ValidationDetailsPanel;
import org.apache.wicket.markup.html.WebMarkupContainer;
import org.apache.wicket.markup.html.basic.Label;
import org.apache.wicket.markup.html.panel.EmptyPanel;
import org.apache.wicket.model.IModel;
import org.apache.wicket.spring.injection.annot.SpringBean;

public class RpkiValidationResultPage extends AbstractPage {

    private static final long serialVersionUID = -4101400840517090913L;
    private static final String ID_ROA_INFO = "roaInfo";

    @SpringBean(name = "roaValidationService")
    private BottomUpRoaValidationService roaValidationService;

    public RpkiValidationResultPage(IModel<byte[]> uploadContents) {
        BottomUpRoaValidationResult result = roaValidationService.validateRoa(uploadContents.getObject());

        add(new Label("validity", result.isValid() ? "valid" : "invalid"));
        add(WicketUtil.getStatusImage("checkmark", result.isValid()));
        add(createValidationDetailsPanel("validationDetailsPanel", result));

        add(createRoaInfoPanel(result));
    }

    private WebMarkupContainer createRoaInfoPanel(BottomUpRoaValidationResult result) {
        if (result.getRoa() != null) {
            return new RoaInfoPanel(ID_ROA_INFO, result.getRoa());
        } else {
            return new EmptyPanel(ID_ROA_INFO);
        }
    }

    private WebMarkupContainer createValidationDetailsPanel(String id, BottomUpRoaValidationResult result) {
        final WebMarkupContainer validationPanel;

        if (isWithDetailedResults(result)) {
            validationPanel = new ValidationDetailsPanel(id, result.getResult());
        } else {
            validationPanel = new EmptyPanel(id);
        }
        return validationPanel;
    }


    private boolean isWithDetailedResults(BottomUpRoaValidationResult result) {
        return result.getResult() != null && result.getResult().getValidatedLocations() != null && result.getResult().getValidatedLocations().size() > 0;
    }
}
