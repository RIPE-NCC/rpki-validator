package net.ripe.rpki.validator.daemon.util;

import java.io.FileReader;
import java.io.IOException;
import java.util.Properties;

public final class RpkiConfigUtil {
    public static final String RPKI_CONFIG = "rpki.config";

    private RpkiConfigUtil() {
    }

    public static Properties loadProperties() throws IOException {
        String filename = System.getProperty(RPKI_CONFIG);

        Properties properties = new Properties();
        properties.load(new FileReader(filename));

        return properties;
    }
}
