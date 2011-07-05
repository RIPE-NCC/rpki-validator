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
