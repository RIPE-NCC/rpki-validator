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
package net.ripe.rpki.validator.daemon.ui;

import net.ripe.rpki.validator.daemon.ui.theme.ThemeProvider;
import org.apache.wicket.Component;
import org.apache.wicket.resource.loader.IStringResourceLoader;
import org.apache.wicket.settings.Settings;
import org.apache.wicket.spring.injection.annot.SpringComponentInjector;
import org.apache.wicket.spring.injection.annot.test.AnnotApplicationContextMock;
import org.apache.wicket.util.tester.WicketTester;
import org.junit.Before;

import java.util.Locale;

/**
 * Created by thies (thies@te-co.nl) on 2/17/11 10:43 AM
 */
public abstract class AbstractWicketTest {
    private AnnotApplicationContextMock mockContext;

    private RpkiValidatorServiceApplication webApp;
    private WicketTester tester;

    @Before
    public final void setup() {
        webApp = new RpkiValidatorServiceApplication() {
            @Override
            protected void springInjection() {
                addComponentInstantiationListener(new SpringComponentInjector(this, getMockContext(), true));
            }
        };
        tester = new WicketTester(webApp);

        getMockContext().putBean("themeProvider", new ThemeProvider("src/test/resources/default_head.html", "src/test/resources/default_header.html", "src/test/resources/default_footer.html"));

        bypassStringResourceLoading();
    }

    protected AnnotApplicationContextMock getMockContext() {
        if (mockContext == null) {
            createContextSetup();
        }

        return mockContext;
    }

    private void createContextSetup() {
        mockContext = new AnnotApplicationContextMock();
    }

    private void bypassStringResourceLoading() {
        ((Settings) webApp.getApplicationSettings()).addStringResourceLoader(new IStringResourceLoader() {

            @Override
            public String loadStringResource(Component component, String key) {
                return key;
            }

            @Override
            public String loadStringResource(Class<?> clazz, String key, Locale locale, String style) {
                return key;
            }
        });
    }

    protected WicketTester getTester() {
        return tester;
    }

    protected RpkiValidatorServiceApplication getWebApp() {
        return webApp;
    }
}