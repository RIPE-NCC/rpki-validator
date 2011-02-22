package net.ripe.rpki.validator.daemon.ui.verification.panel;

import net.ripe.rpki.validator.daemon.ui.AbstractWicketTest;
import net.ripe.rpki.validator.daemon.ui.common.NavigationalCallbackHandler;
import org.apache.wicket.markup.html.panel.Panel;
import org.apache.wicket.util.file.File;
import org.apache.wicket.util.tester.FormTester;
import org.apache.wicket.util.tester.TestPanelSource;
import org.junit.Before;
import org.junit.Test;

import java.io.Serializable;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

public class UploadPanelTest extends AbstractWicketTest implements Serializable {

    private static final long serialVersionUID = 1L;

    private CallbackHandler callbackHandler;

    @Before
    public void setUp() {
        callbackHandler = new CallbackHandler();
    }

    @Test
    public void shouldRender() {
        startPanel();

        getTester().assertNoErrorMessage();
        getTester().assertNoInfoMessage();
    }


    @Test
    public void shouldUploadFile() {
        startPanel();

        File file = new File("src/test/resources/dummyfile.txt");

        FormTester form = getTester().newFormTester("panel:uploadForm");
        form.setFile("fileInput", file, "text/plain");
        form.submit();

        getTester().assertNoErrorMessage();
        getTester().assertNoInfoMessage();

        assertNotNull(callbackHandler.param);
    }

    @Test
    public void shouldNotAcceptEmptyFile() {
        startPanel();

        FormTester form = getTester().newFormTester("panel:uploadForm");
        form.submit();

        getTester().assertErrorMessages(new String[]{"fileInput.Required"});
        getTester().assertNoInfoMessage();

        assertNull(callbackHandler.param);
    }

    @Test
    public void shouldNotAcceptLargeFile() {
        getTester().startPanel(new TestPanelSource() {

            private static final long serialVersionUID = 1L;

            @Override
            public Panel getTestPanel(String panelId) {
                return new UploadPanel(panelId, 1, callbackHandler); // only accept 1kb of data
            }
        });

        File file = new File("src/test/resources/dummyfile.txt");

        FormTester form = getTester().newFormTester("panel:uploadForm");
        form.setFile("fileInput", file, "text/plain");
        form.submit();

        getTester().assertErrorMessages(new String[]{"uploadForm.uploadTooLarge"});
        getTester().assertNoInfoMessage();

        assertNull(callbackHandler.param);
    }


    private void startPanel() {
        getTester().startPanel(new TestPanelSource() {

            private static final long serialVersionUID = 1L;

            @Override
            public Panel getTestPanel(String panelId) {
                return new UploadPanel(panelId, callbackHandler);
            }
        });
    }

    private class CallbackHandler implements NavigationalCallbackHandler<byte[]> {

        private static final long serialVersionUID = 1L;
        
        private byte[] param;

        @Override
        public void callback(byte[] param) {
            this.param = param;
        }
    }


}
