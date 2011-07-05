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
package net.ripe.rpki.validator.daemon.ui.theme;

import net.ripe.rpki.validator.daemon.util.FileResourceUtil;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component("themeProvider")
public class ThemeProvider {

    @Value("${theme.head_section}")
    private String headFile;

    @Value("${theme.body_header}")
    private String headerFile;

    @Value("${theme.body_footer}")
    private String footerFile;

    // for spring
    public ThemeProvider() {
    }

    // for junit tests
    public ThemeProvider(String headFile, String headerFile, String footerFile) {
        this.headFile = headFile;
        this.headerFile = headerFile;
        this.footerFile = footerFile;
    }

    public String getHead() {
        try {
            return FileResourceUtil.readFileContents(headFile);
        } catch (IOException e) {
            throw new IllegalArgumentException("Failed to read head file", e);
        }
    }


    public String getBodyHeader() {
        try {
            return FileResourceUtil.readFileContents(headerFile);
        } catch (IOException e) {
            throw new IllegalArgumentException("Failed to read body header file", e);
        }
    }

    public String getBodyFooter() {
        try {
            return FileResourceUtil.readFileContents(footerFile);
        } catch (IOException e) {
            throw new IllegalArgumentException("Failed to read body footer file", e);
        }
    }


}
