package net.ripe.rpki.validator.daemon.ui.verification.panel;

import net.ripe.commons.certification.cms.roa.RoaCms;
import net.ripe.commons.certification.cms.roa.RoaCmsObjectMother;
import net.ripe.rpki.validator.daemon.ui.AbstractWicketTest;
import org.apache.wicket.markup.html.panel.Panel;
import org.apache.wicket.util.tester.TestPanelSource;
import org.junit.Test;

public class RoaInfoPanelTest extends AbstractWicketTest {
    @Test
    public void shouldRender() {
        RoaCms cms = RoaCmsObjectMother.getRoaCms();

        startPanel(cms);

        getTester().assertNoErrorMessage();
        getTester().assertNoInfoMessage();
    }


    private void startPanel(final RoaCms roaCms) {
        getTester().startPanel(new TestPanelSource() {

            private static final long serialVersionUID = 1L;

            @Override
            public Panel getTestPanel(String panelId) {
                return new RoaInfoPanel(panelId, roaCms);
            }
        });
    }
}
