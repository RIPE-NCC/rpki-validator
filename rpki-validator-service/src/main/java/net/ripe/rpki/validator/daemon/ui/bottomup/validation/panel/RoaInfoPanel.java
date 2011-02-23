package net.ripe.rpki.validator.daemon.ui.bottomup.validation.panel;

import net.ripe.commons.certification.cms.roa.RoaCms;
import net.ripe.commons.certification.cms.roa.RoaPrefix;
import net.ripe.rpki.validator.daemon.service.BottomUpRoaValidationResult;
import net.ripe.rpki.validator.daemon.ui.common.AbstractPanel;

import org.apache.wicket.markup.html.basic.Label;
import org.apache.wicket.markup.html.list.ListItem;
import org.apache.wicket.markup.html.list.ListView;
import org.apache.wicket.model.CompoundPropertyModel;
import org.apache.wicket.model.Model;

public class RoaInfoPanel extends AbstractPanel<RoaCms> {

	private static final long serialVersionUID = 1L;

	public RoaInfoPanel(String id, BottomUpRoaValidationResult result) {
        super(id, new Model<RoaCms>(result.getRoa()));

        add(new Label("asNumber", result.getRoa().getAsn().toString()));

        add(new ListView<RoaPrefix>("prefixes", result.getRoa().getPrefixes()) {
            private static final long serialVersionUID = 1L;

            @Override
            protected void populateItem(final ListItem<RoaPrefix> item) {
                item.setModel(new CompoundPropertyModel<RoaPrefix>(item.getModelObject()));
                item.add(new Label("prefix"));
                item.add(new Label("maximumLength"));
            }
        });

    }
}
