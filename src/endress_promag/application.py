import logging
import time
import asyncio
from typing import Optional

from pydoover.docker import Application

from .app_config import EndressPromagConfig
from .app_tags import EndressPromagTags
from .app_ui import EndressPromagUI
from .eh_meter_wifi import EHMeter
from .promag800_state import (
    ProMag800StateStore,
    ProMag800StateRecord,
    ByteOrder,
)

log = logging.getLogger()


# Register blocks to read - grouped by proximity to minimize reads
# Each tuple is (start_address, num_registers)
MODBUS_REGISTER_BLOCKS = [
    # Measured values and units (2009-2130)
    (2009, 2),      # Volume flow
    (2099, 2),      # Conductivity
    (2103, 2),      # Volume flow unit, Volume unit
    (2109, 1),      # Temperature unit
    (2121, 1),      # Conductivity unit
    (2130, 1),      # Pressure unit

    # Totalizer 1 (2601-2613)
    (2601, 1),      # Totalizer 1 assign
    (2605, 2),      # Totalizer 1 mode, failure mode
    (2608, 1),      # Totalizer 1 control
    (2610, 4),      # Totalizer 1 value + overflow

    # Diagnostics (2624-2744)
    (2624, 1),      # Operating time from restart
    (2631, 1),      # Operating time
    (2732, 2),      # Actual diagnostics, previous diagnostics
    (2736, 10),     # Diagnostics 1-5

    # Totalizer 2 (2801-2813)
    (2801, 1),      # Totalizer 2 assign
    (2805, 2),      # Totalizer 2 mode, failure mode
    (2808, 1),      # Totalizer 2 control
    (2810, 4),      # Totalizer 2 value + overflow

    # Totalizer 3 (3001-3013)
    (3001, 1),      # Totalizer 3 assign
    (3005, 2),      # Totalizer 3 mode, failure mode
    (3008, 1),      # Totalizer 3 control
    (3010, 4),      # Totalizer 3 value + overflow

    # Totalizer units (4604-4606)
    (4604, 3),      # Totalizer 1-3 units

    # Modbus config (4910-4920)
    (4910, 1),      # Bus address
    (4912, 1),      # Baudrate
    (4914, 2),      # Parity, Byte order
    (4916, 2),      # Telegram delay
    (4918, 1),      # Locking status
    (4920, 1),      # Failure mode

    # Flow velocity and pressure (5085-5088)
    (5085, 4),      # Flow velocity + pressure

    # Sensor config (5101-5106)
    (5101, 1),      # Low flow cutoff
    (5104, 2),      # Low flow cutoff off value
    (5106, 1),      # Empty pipe detection

    # Battery status (9772-9773, 9872-9873)
    (9772, 2),      # Estimated battery lifetime
    (9872, 2),      # Battery charge state
]


# A decorator to cache a value if it is not None
def cached_value(func):
    def wrapper(self):
        result = func(self)
        if result is None:
            if not self.meter_offline:
                return self._last_non_null.get(func.__name__, None)
        self._last_non_null[func.__name__] = result
        return result
    return wrapper


class EndressPromagApplication(Application):
    config: EndressPromagConfig  # these aren't necessary, but help your IDE provide autocomplete!
    tags: EndressPromagTags
    ui: EndressPromagUI

    config_cls = EndressPromagConfig
    tags_cls = EndressPromagTags
    ui_cls = EndressPromagUI

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.loop_target_period = 5  # seconds
        self.last_status_print = time.time()

        self._last_non_null = {}
        self._last_non_null_age = None

        self.started: float = time.time()

        # Modbus state store for ProMag 800
        self._modbus_state_store: Optional[ProMag800StateStore] = None
        self._last_modbus_update: Optional[float] = None

    @property
    def use_modbus(self) -> bool:
        """Check if we should use Modbus interface instead of WiFi."""
        return self.config.modbus_id.value is not None

    async def setup(self):
        if self.use_modbus:
            # Initialize modbus state store
            self._modbus_state_store = ProMag800StateStore(byte_order=ByteOrder.ORDER_0123)
            log.info(f"Using Modbus interface, ID: {self.config.modbus_id.value}")
        else:
            # Initialize WiFi interface
            self.eh_meter = EHMeter(
                host=self.config.eh_meter_host.value,
                password=self.config.eh_meter_password.value,
                port=self.config.eh_meter_port.value,
            )
            log.info(f"Using WiFi interface, Host: {self.config.eh_meter_host.value}")

    async def main_loop(self):
        if self.use_modbus:
            await self.update_via_modbus()
        else:
            await self.eh_meter.update()
            correct_serial = self.ensure_serial_number()
            if not correct_serial:
                log.warning("Serial number mismatch, Sleeping Longer")
                await asyncio.sleep(25)

        self.ensure_meter_online()
        self.print_status()
        await self.update_tags()

    async def update_tags(self):
        await self.tags.volume_flow.set(self.volume_flow)
        await self.tags.mass_flow.set(self.mass_flow)
        await self.tags.conductivity.set(self.conductivity)
        await self.tags.totaliser_1.set(self.totaliser_1)
        await self.tags.last_read_time.set(time.time() - self.last_read_age)
        await self.tags.meter_online.set(not self.meter_offline)
        await self.tags.meter_ok.set(not self.has_active_diagnostic)

    def ensure_serial_number(self):
        """Validate serial number (WiFi mode only)."""
        if self.use_modbus:
            return True
        if self.config.eh_meter_serial_number.value is None or self.config.eh_meter_serial_number.value == "":
            return True
        serial_number = self.eh_meter.get_value("Serial number")
        if not serial_number or serial_number != self.config.eh_meter_serial_number.value:
            self.eh_meter.clear_values()
            return False
        return True

    def ensure_meter_online(self):
        """Clear cached values if meter is offline."""
        if self.meter_offline:
            if self.use_modbus:
                # For modbus, the state store handles this
                pass
            else:
                self.eh_meter.clear_values()

    def print_status(self):
        # If there hasn't been an update since the last print, print a warning
        if self.last_read_age > (time.time() - self.last_status_print):
            log.warning("No connection to meter")
        else:
            log.info(f"Volume flow: {self.volume_flow}, Totaliser 1: {self.totaliser_1}")
        self.last_status_print = time.time()

    async def update_via_modbus(self):
        """Read register data from the ProMag 800 via Modbus interface."""
        if not self.use_modbus:
            return

        bus_id = self.config.modbus_config.name.value
        modbus_id = self.config.modbus_id.value

        # Read all register blocks and combine into a dict
        register_values: dict[int, int] = {}
        read_success = False

        for start_address, num_registers in MODBUS_REGISTER_BLOCKS:
            try:
                values = await self.modbus_iface.read_registers(
                    bus_id=bus_id,
                    modbus_id=modbus_id,
                    start_address=start_address,
                    num_registers=num_registers,
                    register_type=3,  # Holding registers (function code 03)
                )

                if values is not None:
                    read_success = True
                    # Handle single value vs list
                    if isinstance(values, int):
                        values = [values]
                    # Map register addresses to values
                    for i, val in enumerate(values):
                        register_values[start_address + i] = val
                else:
                    log.debug(f"Failed to read registers {start_address}-{start_address + num_registers - 1}")

            except Exception as e:
                log.warning(f"Error reading modbus registers {start_address}-{start_address + num_registers - 1}: {e}")

        # Update the state store
        if read_success and register_values:
            self._modbus_state_store.update(register_values)
            self._last_modbus_update = time.time()
            log.debug(f"Modbus update successful, read {len(register_values)} registers")
        else:
            # Mark as uncontactable
            self._modbus_state_store.update(None)
            log.warning("Modbus read failed - no valid data received")

    @property
    def modbus_state(self) -> Optional[ProMag800StateRecord]:
        """Get the current modbus state record."""
        if self._modbus_state_store is None:
            return None
        return self._modbus_state_store.state

    @property
    @cached_value
    def volume_flow(self):
        """Get volume flow rate in m3/h."""
        if self.use_modbus:
            state = self.modbus_state
            if state is None:
                return None
            return state.volume_flow
        else:
            value = self.eh_meter.get_value("Volume flow")
            if value is None:
                return None
            return float(value)

    @property
    @cached_value
    def mass_flow(self):
        """Get mass flow rate.

        Note: ProMag 800 via Modbus doesn't have mass flow directly -
        it's a volumetric meter. Returns None for modbus mode.
        """
        if self.use_modbus:
            # ProMag 800 is volumetric, no direct mass flow
            # Could calculate from volume_flow * density if needed
            return None
        else:
            value = self.eh_meter.get_value("Mass flow")
            if value is None:
                return None
            return float(value)

    @property
    @cached_value
    def conductivity(self):
        """Get conductivity in uS/cm."""
        if self.use_modbus:
            state = self.modbus_state
            if state is None:
                return None
            return state.conductivity
        else:
            value = self.eh_meter.get_value("Conductivity")
            if value is None or value == "" or value == "-nan":
                return None
            try:
                return float(value)
            except ValueError:
                return None

    @property
    @cached_value
    def totaliser_1(self):
        """Get totalizer 1 value."""
        if self.use_modbus:
            state = self.modbus_state
            if state is None:
                return None
            return state.totalizer_1_value
        else:
            value = self.eh_meter.get_value("Totalizer value 1")
            if value is None:
                return None
            return float(value)

    @property
    @cached_value
    def totaliser_2(self):
        """Get totalizer 2 value."""
        if self.use_modbus:
            state = self.modbus_state
            if state is None:
                return None
            return state.totalizer_2_value
        else:
            value = self.eh_meter.get_value("Totalizer value 2")
            if value is None:
                return None
            return float(value)

    @property
    @cached_value
    def totaliser_3(self):
        """Get totalizer 3 value."""
        if self.use_modbus:
            state = self.modbus_state
            if state is None:
                return None
            return state.totalizer_3_value
        else:
            value = self.eh_meter.get_value("Totalizer value 3")
            if value is None:
                return None
            return float(value)

    @property
    @cached_value
    def flow_velocity(self):
        """Get flow velocity (modbus only)."""
        if self.use_modbus:
            state = self.modbus_state
            if state is None:
                return None
            return state.flow_velocity
        return None

    @property
    @cached_value
    def pressure(self):
        """Get pressure (modbus only)."""
        if self.use_modbus:
            state = self.modbus_state
            if state is None:
                return None
            return state.pressure
        return None

    @property
    @cached_value
    def battery_charge_state(self):
        """Get battery charge state percentage (modbus only)."""
        if self.use_modbus:
            state = self.modbus_state
            if state is None:
                return None
            return state.battery_charge_state
        return None

    @property
    @cached_value
    def estimated_battery_lifetime(self):
        """Get estimated battery lifetime (modbus only)."""
        if self.use_modbus:
            state = self.modbus_state
            if state is None:
                return None
            return state.estimated_battery_lifetime
        return None

    @property
    def has_active_diagnostic(self) -> bool:
        """Check if there's an active diagnostic code (modbus only)."""
        if self.use_modbus:
            state = self.modbus_state
            if state is None:
                return False
            return state.has_active_diagnostic
        return False

    @property
    def actual_diagnostics(self) -> Optional[int]:
        """Get the current diagnostic code (modbus only)."""
        if self.use_modbus:
            state = self.modbus_state
            if state is None:
                return None
            return state.actual_diagnostics
        return None

    @property
    def last_read_age(self):
        """Get the age of the last successful read in seconds."""
        if self.use_modbus:
            if self._last_modbus_update is None:
                if self._last_non_null_age is not None:
                    return time.time() - self._last_non_null_age
                return time.time() - self.started
            age = time.time() - self._last_modbus_update
            self._last_non_null_age = self._last_modbus_update
            return age
        else:
            age = self.eh_meter.value_update_age("Totalizer value 1")
            if age is None:
                if self._last_non_null_age is not None:
                    return time.time() - self._last_non_null_age
                return time.time() - self.started
            self._last_non_null_age = time.time() - age
            return age

    @property
    def meter_offline(self):
        """Check if the meter is considered offline based on no-comms timeout."""
        return self.last_read_age > self.config.no_comms_timeout.value * 60

    @property
    def is_contactable(self) -> bool:
        """Check if meter is currently contactable."""
        if self.use_modbus:
            if self._modbus_state_store is None:
                return False
            return self._modbus_state_store.is_contactable
        return not self.meter_offline