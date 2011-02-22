package net.ripe.rpki.validator.daemon.ui.verification;

import net.ripe.rpki.validator.daemon.ui.common.AbstractPage;
import net.ripe.rpki.validator.daemon.ui.common.NavigationalCallbackHandler;
import net.ripe.rpki.validator.daemon.ui.verification.panel.UploadPanel;
import org.apache.wicket.model.Model;

/**
 * Created by thies (thies@te-co.nl) on 2/17/11 10:39 AM
 */
public class RpkiUploadPage extends AbstractPage {

    private static final long serialVersionUID = 1l;

    public RpkiUploadPage() {
        add(new UploadPanel("uploadPanel", new CallbackHandler()));
    }

    private class CallbackHandler implements NavigationalCallbackHandler<byte[]> {
        private static final long serialVersionUID = 1l;

        @Override
        public void callback(byte[] fileContents) {
            Model<byte[]> fileContentsModel = new Model<byte[]>(fileContents);

            RpkiUploadPage.this.setResponsePage(new RpkiValidationResultPage(fileContentsModel));
        }
    }
}
