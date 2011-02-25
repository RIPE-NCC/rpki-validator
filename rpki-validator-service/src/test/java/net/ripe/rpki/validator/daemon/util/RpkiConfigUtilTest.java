package net.ripe.rpki.validator.daemon.util;

import org.junit.Test;

import java.io.IOException;
import java.util.Properties;

import static org.junit.Assert.assertTrue;

public class RpkiConfigUtilTest {
    @Test
    public void shouldLoadProperties() throws IOException {
        System.getProperties().put(RpkiConfigUtil.RPKI_CONFIG, "src/test/resources/rpki-vs.properties");

        Properties properties = RpkiConfigUtil.loadProperties();

        String port = (String) properties.get("jetty.port");
        int i = Integer.parseInt(port);
        assertTrue(i > 0);

    }
}
