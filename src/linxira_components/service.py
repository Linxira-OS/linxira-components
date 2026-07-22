from __future__ import annotations

import json
import os
import sys
import threading

from .errors import ComponentsError
from .system_transactions import SystemTransactionStore
from .worker import launch_system_worker


BUS_NAME = "org.linxira.Components1"
OBJECT_PATH = "/org/linxira/Components1"
INTERFACE = "org.linxira.Components1"
POLKIT_AUTHORITY = "org.freedesktop.PolicyKit1"
POLKIT_PATH = "/org/freedesktop/PolicyKit1/Authority"
POLKIT_INTERFACE = "org.freedesktop.PolicyKit1.Authority"


def _imports():
    try:
        import dbus
        import dbus.service
        from dbus.mainloop.glib import DBusGMainLoop
        from gi.repository import GLib
    except ImportError as exc:
        raise RuntimeError("linxira-components service requires python-dbus and python-gobject") from exc
    return dbus, DBusGMainLoop, GLib


def create_service_class(dbus, idle_add=None):
    schedule = idle_add or (lambda callback, *args: callback(*args))

    class ComponentsService(dbus.service.Object):
        def __init__(self, bus, store=None):
            self.bus = bus
            self.store = SystemTransactionStore(mutation_executor=launch_system_worker) if store is None else store
            self.apply_active = threading.Event()
            self.plan_active = threading.Event()
            super().__init__(bus, OBJECT_PATH)

        def _uid(self, sender):
            try:
                return int(self.bus.get_unix_user(sender))
            except Exception as exc:
                raise dbus.DBusException(
                    "Cannot determine D-Bus caller UID",
                    name="org.linxira.Components1.Error.Authorization",
                ) from exc

        def _authorize(self, sender, action_id):
            authority_object = self.bus.get_object(POLKIT_AUTHORITY, POLKIT_PATH)
            authority = dbus.Interface(authority_object, POLKIT_INTERFACE)
            subject = (
                "system-bus-name",
                {"name": dbus.String(sender, variant_level=1)},
            )
            authorized, _challenge, _details = authority.CheckAuthorization(
                subject,
                action_id,
                {},
                dbus.UInt32(1),
                "",
                timeout=120,
            )
            if not authorized:
                raise dbus.DBusException(
                    "Authorization denied",
                    name="org.linxira.Components1.Error.Authorization",
                )

        def _call(self, callback):
            try:
                return callback()
            except ComponentsError as exc:
                raise dbus.DBusException(
                    str(exc), name=f"org.linxira.Components1.Error.{exc.code}"
                ) from exc

        @dbus.service.method(
            INTERFACE,
            in_signature="ss",
            out_signature="ss",
            sender_keyword="sender",
            async_callbacks=("return_callback", "error_callback"),
        )
        def CreateSystemPlan(
            self, operation_id, parameters_json, sender=None,
            return_callback=None, error_callback=None,
        ):
            if self.apply_active.is_set() or self.plan_active.is_set():
                raise dbus.DBusException(
                    "A system transaction is already running",
                    name="org.linxira.Components1.Error.Busy",
                )
            self._authorize(sender, "org.linxira.components.inspect")
            uid = self._uid(sender)
            self.plan_active.set()

            def work():
                try:
                    plan = self.store.create_plan(str(operation_id), str(parameters_json), uid)
                    schedule(
                        return_callback, plan["id"],
                        json.dumps(plan, ensure_ascii=True, sort_keys=True),
                    )
                except ComponentsError as exc:
                    schedule(error_callback, dbus.DBusException(
                        str(exc), name=f"org.linxira.Components1.Error.{exc.code}"
                    ))
                except Exception:
                    schedule(error_callback, dbus.DBusException(
                        "System plan creation failed",
                        name="org.linxira.Components1.Error.Internal",
                    ))
                finally:
                    self.plan_active.clear()

            threading.Thread(target=work, daemon=True, name="linxira-system-plan").start()

        @dbus.service.method(
            INTERFACE,
            in_signature="ss",
            out_signature="ss",
            sender_keyword="sender",
            async_callbacks=("return_callback", "error_callback"),
        )
        def ConfirmAndApplySystemPlan(
            self, plan_id, plan_digest, sender=None, return_callback=None, error_callback=None
        ):
            uid = self._uid(sender)
            action = self._call(lambda: self.store.action_for_plan(str(plan_id), uid))
            self._authorize(sender, action)
            if self.apply_active.is_set() or self.plan_active.is_set():
                raise dbus.DBusException(
                    "A system mutation is already running",
                    name="org.linxira.Components1.Error.Busy",
                )
            self.apply_active.set()

            def work():
                try:
                    receipt = self.store.confirm_and_apply(str(plan_id), str(plan_digest), uid)
                    schedule(
                        return_callback, receipt["id"],
                        json.dumps(receipt, ensure_ascii=True, sort_keys=True),
                    )
                except ComponentsError as exc:
                    error = dbus.DBusException(
                        str(exc), name=f"org.linxira.Components1.Error.{exc.code}"
                    )
                    schedule(error_callback, error)
                except Exception as exc:
                    error = dbus.DBusException(
                        "System transaction failed",
                        name="org.linxira.Components1.Error.Internal",
                    )
                    error.__cause__ = exc
                    schedule(error_callback, error)
                finally:
                    self.apply_active.clear()

            threading.Thread(target=work, daemon=True, name="linxira-system-apply").start()

        @dbus.service.method(
            INTERFACE,
            in_signature="s",
            out_signature="s",
            sender_keyword="sender",
        )
        def GetSystemReceipt(self, receipt_id, sender=None):
            self._authorize(sender, "org.linxira.components.inspect")
            receipt = self._call(
                lambda: self.store.get_receipt(str(receipt_id), self._uid(sender))
            )
            return json.dumps(receipt, ensure_ascii=True, sort_keys=True)

        @dbus.service.method(INTERFACE, in_signature="", out_signature="u")
        def GetInterfaceVersion(self):
            return dbus.UInt32(1)

    return ComponentsService


def main() -> int:
    if os.geteuid() != 0:
        print("linxira-components service must run as root", file=sys.stderr)
        return 1
    dbus, DBusGMainLoop, GLib = _imports()
    DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()
    name = dbus.service.BusName(BUS_NAME, bus=bus, do_not_queue=True)
    service_class = create_service_class(dbus, GLib.idle_add)
    service = service_class(bus)
    loop = GLib.MainLoop()
    try:
        loop.run()
    finally:
        service.remove_from_connection()
        del name
    return 0
