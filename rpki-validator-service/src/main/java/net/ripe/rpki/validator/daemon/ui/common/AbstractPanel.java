package net.ripe.rpki.validator.daemon.ui.common;

import org.apache.wicket.markup.html.panel.Panel;
import org.apache.wicket.model.IModel;

import java.io.Serializable;

public class AbstractPanel<T extends Serializable> extends Panel {

    private static final long serialVersionUID = -8719626072421914732L;

    protected AbstractPanel(String id) {
        super(id);
    }

    protected AbstractPanel(String id, IModel<T> model) {
        super(id, model);
    }

    @SuppressWarnings("unchecked")
    protected T getPanelModelObject() {
        return (T) getDefaultModelObject();
    }
}
