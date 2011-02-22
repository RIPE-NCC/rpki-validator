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
