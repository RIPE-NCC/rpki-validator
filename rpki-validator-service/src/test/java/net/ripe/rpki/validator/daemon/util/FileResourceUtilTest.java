package net.ripe.rpki.validator.daemon.util;

import org.junit.After;
import org.junit.Test;

import java.io.File;

import static org.junit.Assert.assertTrue;

public class FileResourceUtilTest {
    @After
    public void tearDown() {
        System.getProperties().remove(RpkiConfigUtil.RPKI_CONFIG);
    }

    @Test
    public void shouldPrepend() {
        System.setProperty(RpkiConfigUtil.RPKI_CONFIG, "src/test/resources/dummyfile.txt");

        File file = FileResourceUtil.findFileInPathOrConfigPath("FileResourceUtilTestFile.txt");

        assertTrue(file.exists());
    }
}
