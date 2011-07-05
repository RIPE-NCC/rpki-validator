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

import net.ripe.rpki.validator.daemon.ui.AbstractWicketTest;
import net.ripe.rpki.validator.daemon.ui.bottomup.validation.panel.UploadPanel;
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
