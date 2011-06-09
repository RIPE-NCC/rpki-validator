package net.ripe.rpki.validator.daemon.util;

import java.io.File;
import java.io.IOException;

import org.apache.commons.io.FileUtils;

public final class FileResourceUtil {

    // Util class not intended to be instantiated
    private FileResourceUtil() {
    }

    /**
     * <p>
     * Find the named file and return the contents.
     * </p>
     * <p/>
     * Will try the following in order:<br />
     * <li>relative path
     * <li>absolute path
     * <li>path relative to the parent directory of the rpki.config file
     *
     * @throws IllegalArgumentException if file can not be found
     * @throws IOException              when reading fails for some reason
     */
    public static String readFileContents(String filename) throws IOException {
        File file = findFileInPathOrConfigPath(filename);
        return FileUtils.readFileToString(file);
    }

    /**
     * <p>
     * Find the named file and return the contents.
     * </p>
     * <p/>
     * Will try the following in order:<br />
     * <li>relative path
     * <li>absolute path
     * <li>path relative to the parent directory of the rpki.config file
     *
     * @throws IllegalArgumentException if file can not be found
     * @throws IOException              when reading fails for some reason
     */
    public static File findFileInPathOrConfigPath(String filename) {
        File file = new File(filename);

        if (!file.exists()) {
            file = prefixWithConfigPath(filename);

            if (!file.exists()) {
                throw new IllegalArgumentException(file.getAbsolutePath() + " or " + new File(filename).getAbsolutePath() + " does not exist");
            }
        }
        return file;
    }

    private static File prefixWithConfigPath(String filename) {
        String rpkiConfig = System.getProperty(RpkiConfigUtil.RPKI_CONFIG);
        String rpkiPath = new File(rpkiConfig).getParent();
        return new File(rpkiPath, filename);
    }

}
