package net.ripe.rpki.validator.daemon.ui.verification;

import net.ripe.rpki.validator.daemon.ui.AbstractWicketTest;
import org.junit.Test;

public class RpkiUploadPageTest extends AbstractWicketTest {

    @Test
    public void shouldRender() {
        getTester().startPage(RpkiUploadPage.class);

        getTester().assertNoErrorMessage();
        getTester().assertNoInfoMessage();
        getTester().assertRenderedPage(RpkiUploadPage.class);
    }
}
