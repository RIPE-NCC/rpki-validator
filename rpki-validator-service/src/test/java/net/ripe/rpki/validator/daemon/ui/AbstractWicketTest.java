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