package net.ripe.rpki.validator.daemon.ui;

import net.ripe.rpki.validator.daemon.ui.verification.RpkiUploadPage;
import net.ripe.rpki.validator.daemon.ui.verification.RpkiValidationResultPage;
import org.apache.wicket.protocol.http.WebApplication;
import org.apache.wicket.request.target.coding.HybridUrlCodingStrategy;
import org.apache.wicket.spring.injection.annot.SpringComponentInjector;
import org.springframework.stereotype.Component;

@Component
public class RpkiValidatorServiceApplication extends WebApplication {

    @Override
    protected void init() {
        mountPages();
        springInjection();
        getMarkupSettings().setStripWicketTags(true);
    }

    @Override
    public Class<RpkiUploadPage> getHomePage() {
        return RpkiUploadPage.class;
    }

    void springInjection() {
        addComponentInstantiationListener(new SpringComponentInjector(this));
    }

    private void mountPages() {
        mount(new HybridUrlCodingStrategy("/rpkiresults", RpkiValidationResultPage.class));
    }

}
