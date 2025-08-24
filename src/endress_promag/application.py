import logging
import time
import asyncio

from pydoover.docker import Application
from pydoover import ui

from .app_config import EndressPromagConfig
from .app_ui import EndressPromagUI
from .eh_meter import EHMeter

log = logging.getLogger()

class EndressPromagApplication(Application):
    config: EndressPromagConfig  # not necessary, but helps your IDE provide autocomplete!

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.loop_target_period = 5 # seconds
        self.last_status_print = time.time()

        self.started: float = time.time()
        self.ui: EndressPromagUI = None

    async def setup(self):
        self.ui = EndressPromagUI(self)
        self.ui_manager.set_display_name(self.config.meter_name.value)
        self.ui_manager.add_children(*self.ui.fetch())

        self.eh_meter = EHMeter(
            host=self.config.eh_meter_host.value,
            password=self.config.eh_meter_password.value,
            port=self.config.eh_meter_port.value,
        )

    async def main_loop(self):
        await self.eh_meter.update()
        correct_serial = self.ensure_serial_number()
        self.ensure_meter_online()
        self.print_status()
        self.ui_manager.set_display_name(self.get_display_name())
        await self.update_tags()
        self.ui.update()
        if not correct_serial:
            log.warning("Serial number mismatch, Sleeping Longer")
            await asyncio.sleep(25)

    async def update_tags(self):
        update = {
            "flow_m3h": self.volume_flow,
            "flow_kgmin": self.mass_flow,
            "totaliser_1": self.totaliser_1,
        }
        await self.set_tags(update)

    def get_display_name(self):
        name = self.config.meter_name.value
        if self.meter_offline:
            name += " - Offline"
        else:
            flow = self.volume_flow
            if flow is None or flow == 0 or flow < 0:
                name += " - No Flow"
            else:
                name += f" - {flow:.2f} m3/h"
        return name

    def ensure_serial_number(self):
        if self.config.eh_meter_serial_number.value is None or self.config.eh_meter_serial_number.value == "":
            return True
        serial_number = self.eh_meter.get_value("Serial number")
        if not serial_number or serial_number != self.config.eh_meter_serial_number.value:
            self.eh_meter.clear_values()
            # log.warning(f"Serial number mismatch: {serial_number} != {self.config.eh_meter_serial_number.value}")
            return False
        return True

    def ensure_meter_online(self):
        if self.meter_offline:
            self.eh_meter.clear_values()

    def print_status(self):
        # If there hasn't been an update since the last print, print a warning
        if self.last_read_age > (time.time() - self.last_status_print):
            log.warning("No connection to meter")
        else:
            log.info(f"Volume flow: {self.volume_flow}, Totaliser 1: {self.totaliser_1}")
        self.last_status_print = time.time()

    @property
    def volume_flow(self):
        value = self.eh_meter.get_value("Volume flow")
        if value is None:
            return None
        return float(value)
    
    @property
    def mass_flow(self):
        value = self.eh_meter.get_value("Mass flow")
        if value is None:
            return None
        return float(value)
    
    @property
    def conductivity(self):
        value = self.eh_meter.get_value("Conductivity")
        if value is None or value == "" or value == "-nan":
            return None
        try:
            return float(value)
        except ValueError:
            return None

    @property
    def totaliser_1(self):
        value = self.eh_meter.get_value("Totalizer value 1")
        if value is None:
            return None
        return float(value)

    @property
    def last_read_age(self):
        age = self.eh_meter.value_update_age("Totalizer value 1")
        if age is None:
            age = time.time() - self.started
        return age

    @property
    def meter_offline(self):
        return self.last_read_age > self.config.no_comms_timeout.value * 60