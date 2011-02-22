package net.ripe.rpki.validator.daemon.ui.common;

import java.io.Serializable;

public interface NavigationalCallbackHandler<T extends Serializable> extends Serializable {
    void callback(T param);
}
