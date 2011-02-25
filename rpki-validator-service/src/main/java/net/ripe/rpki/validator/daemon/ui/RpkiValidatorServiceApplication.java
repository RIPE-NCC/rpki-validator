package net.ripe.rpki.validator.daemon.ui;

import net.ripe.rpki.validator.daemon.ui.bottomup.validation.RoaValidationPage;

import org.apache.wicket.protocol.http.WebApplication;
import org.apache.wicket.spring.injection.annot.SpringComponentInjector;
import org.springframework.stereotype.Component;

@Component
public class RpkiValidatorServiceApplication extends WebApplication {

    @Override
    protected void init() {
        springInjection();
        getMarkupSettings().setStripWicketTags(true);
    }

    @Override
    public Class<RoaValidationPage> getHomePage() {
        return RoaValidationPage.class;
    }

    void springInjection() {
        addComponentInstantiationListener(new SpringComponentInjector(this));
    }

}
