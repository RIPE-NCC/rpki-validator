package net.ripe.rpki.validator.daemon.ui.theme;

import net.ripe.rpki.validator.daemon.util.RpkiConfigUtil;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.File;

import static org.junit.Assert.assertNotNull;

public class ThemeProviderTest {
    @Before
    public void setUp() {
        System.getProperties().put(RpkiConfigUtil.RPKI_CONFIG, new File("src/test/resources/dummyfile.txt").getAbsolutePath());
    }

    @After
    public void tearDown() {
        System.getProperties().remove(RpkiConfigUtil.RPKI_CONFIG);
    }

    @Test
    public void shouldReadHeaderAndFooter() {
        ThemeProvider provider = new ThemeProvider("default_head.html", "default_header.html", "default_footer.html");

        assertNotNull(provider.getBodyHeader());
        assertNotNull(provider.getBodyFooter());
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldReadHeaderButNoFooter() {
        ThemeProvider provider = new ThemeProvider("default_head.html", "src/test/resources/default_header.html", "idontexist");

        assertNotNull(provider.getBodyHeader());
        assertNotNull(provider.getBodyFooter());
    }

}
