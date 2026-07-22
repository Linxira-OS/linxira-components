from __future__ import annotations

import os
from pathlib import Path
import tempfile
import threading

def test_service_registers_and_answers_on_a_private_bus():
    import pytest
    if not os.environ.get("DBUS_SESSION_BUS_ADDRESS"):
        pytest.skip("requires dbus-run-session")
    dbus = pytest.importorskip("dbus")
    import dbus.service
    pytest.importorskip("gi")
    from dbus.mainloop.glib import DBusGMainLoop
    from gi.repository import GLib

    from linxira_components.service import BUS_NAME, INTERFACE, OBJECT_PATH, create_service_class
    from linxira_components.system_transactions import SystemTransactionStore

    DBusGMainLoop(set_as_default=True)
    with tempfile.TemporaryDirectory() as directory:
        service_bus = dbus.SessionBus(private=True)
        client_bus = dbus.SessionBus(private=True)
        name = dbus.service.BusName(BUS_NAME, bus=service_bus, do_not_queue=True)
        store = SystemTransactionStore(Path(directory) / "state", Path(directory) / "root")
        service = create_service_class(dbus)(service_bus, store)
        loop = GLib.MainLoop()
        thread = threading.Thread(target=loop.run, daemon=True)
        thread.start()
        try:
            proxy = client_bus.get_object(BUS_NAME, OBJECT_PATH)
            interface = dbus.Interface(proxy, INTERFACE)
            assert int(interface.GetInterfaceVersion(timeout=5)) == 1
        finally:
            loop.quit()
            thread.join(timeout=5)
            service.remove_from_connection()
            del name
            client_bus.close()
            service_bus.close()
