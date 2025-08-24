import logging
import time

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
        self.print_status()
        self.ui.update()

    async def update_tags(self):
        update = {
            "flow_m3h": self.volume_flow,
            "flow_kgmin": self.mass_flow,
            "totaliser_1": self.totaliser_1,
        }
        await self.set_tags(update)

    def print_status(self):
        if self.last_read_age > 1:
            log.warning("No connection to meter")
        else:
            log.info(f"Volume flow: {self.volume_flow}, Totaliser 1: {self.totaliser_1}")

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