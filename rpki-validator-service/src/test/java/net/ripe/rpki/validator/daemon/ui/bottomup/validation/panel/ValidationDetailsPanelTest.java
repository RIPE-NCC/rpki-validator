package net.ripe.rpki.validator.daemon.ui.bottomup.validation.panel;

import net.ripe.commons.certification.validation.ValidationResult;
import net.ripe.rpki.validator.daemon.ui.AbstractWicketTest;
import net.ripe.rpki.validator.daemon.ui.bottomup.validation.panel.ValidationDetailsPanel;

import org.apache.wicket.markup.html.panel.Panel;
import org.apache.wicket.util.tester.TestPanelSource;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class ValidationDetailsPanelTest extends AbstractWicketTest {
    public ValidationResult validationResult;

    @Before
    public void setUpValidationResult() {
        validationResult = new ValidationResult();
        validationResult.push("objects.crl.valid");
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
