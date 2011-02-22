package net.ripe.rpki.validator.daemon.ui.common;

import org.apache.wicket.markup.html.image.ContextImage;

public final class WicketUtil {
    private WicketUtil() {
    }

    public static ContextImage getStatusImage(String id, boolean status) {
        String imagePath = status ? "tick.gif" : "cross.gif";
        return new ContextImage(id, "static/images/" + imagePath);
    }
}
