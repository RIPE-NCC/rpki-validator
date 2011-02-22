package net.ripe.rpki.validator.daemon.ui.common;

import net.ripe.rpki.validator.daemon.ui.theme.ThemeProvider;
import org.apache.wicket.markup.html.WebPage;
import org.apache.wicket.markup.html.basic.Label;
import org.apache.wicket.spring.injection.annot.SpringBean;

public abstract class AbstractPage extends WebPage {
    private static final long serialVersionUID = 245103704509486509L;
    @SpringBean(name = "themeProvider")
    private ThemeProvider themeProvider;

    protected AbstractPage() {
        initPage();
    }

    private void initPage() {
        Label head = new Label("head", themeProvider.getHead());
        head.setEscapeModelStrings(false);
        add(head);


        Label header = new Label("header", themeProvider.getBodyHeader());
        header.setEscapeModelStrings(false);
        add(header);

        Label footer = new Label("footer", themeProvider.getBodyFooter());
        footer.setEscapeModelStrings(false);
        add(footer);
    }
}
