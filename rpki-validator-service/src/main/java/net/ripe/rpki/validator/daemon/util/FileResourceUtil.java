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
