package net.ripe.rpki.validator.daemon.ui.bottomup.validation.panel;

import net.ripe.commons.certification.cms.roa.RoaCms;
import net.ripe.commons.certification.cms.roa.RoaCmsObjectMother;
import net.ripe.rpki.validator.daemon.service.BottomUpRoaValidationResult;
import net.ripe.rpki.validator.daemon.ui.AbstractWicketTest;
import net.ripe.rpki.validator.daemon.ui.bottomup.validation.panel.RoaInfoPanel;

import org.apache.wicket.markup.html.panel.Panel;
import org.apache.wicket.util.tester.TestPanelSource;
import org.junit.Test;

public class RoaInfoPanelTest extends AbstractWicketTest {
    @Test
    public void shouldRender() {
        RoaCms cms = RoaCmsObjectMother.getRoaCms();

        BottomUpRoaValidationResult result = new BottomUpRoaValidationResult(cms, null);
        
        startPanel(result);

        getTester().assertNoErrorMessage();
        getTester().assertNoInfoMessage();
    }


    private void startPanel(final BottomUpRoaValidationResult result) {
        getTester().startPanel(new TestPanelSource() {

            private static final long serialVersionUID = 1L;

            @Override
            public Panel getTestPanel(String panelId) {
                return new RoaInfoPanel(panelId, result);
            }
        });
    }
}
