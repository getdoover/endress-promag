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


# Register blocks to read each loop - (E+H register number, num_registers).
#
MODBUS_REGISTER_BLOCKS = [
    (2009, 2),      # Volume flow (float)
    (2099, 2),      # Conductivity (float)
    (2610, 2),      # Totalizer 1 value (float) - value only, NOT the +overflow
    (2732, 1),      # Actual diagnostics (drives meter_ok)

    # --- Additional registers, disabled for now -----------------------------
    # The meter exposes these but nothing currently displays them, so we don't
    # pay the per-block settle delay / miss risk for them. Re-enable individually
    # if/when they're surfaced as tags. NOTE: keep any read to num_registers <= 2
    # (the meter fails longer reads as a unit - the old (2610, 4) is why the
    # totaliser was blank), so the widened blocks below are split accordingly.
    #
    # Measured values and units
    # (2103, 2),    # Volume flow unit, Volume unit
    # (2109, 1),    # Temperature unit
    # (2121, 1),    # Conductivity unit
    # (2130, 1),    # Pressure unit
    #
    # Totalizer 1 config
    # (2601, 1),    # Totalizer 1 assign
    # (2605, 2),    # Totalizer 1 mode, failure mode
    # (2608, 1),    # Totalizer 1 control
    # (2612, 2),    # Totalizer 1 overflow (was part of the old (2610, 4))
    #
    # Diagnostics
    # (2624, 1),    # Operating time from restart
    # (2631, 1),    # Operating time
    # (2733, 1),    # Previous diagnostics (was part of the old (2732, 2))
    # (2736, 2),    # Diagnostic 1   (old (2736, 10) split into <=2 reg reads)
    # (2738, 2),    # Diagnostic 2
    # (2740, 2),    # Diagnostic 3
    # (2742, 2),    # Diagnostic 4
    # (2744, 2),    # Diagnostic 5
    #
    # Totalizer 2
    # (2801, 1),    # Totalizer 2 assign
    # (2805, 2),    # Totalizer 2 mode, failure mode
    # (2808, 1),    # Totalizer 2 control
    # (2810, 2),    # Totalizer 2 value (was (2810, 4) incl. overflow)
    # (2812, 2),    # Totalizer 2 overflow
    #
    # Totalizer 3
    # (3001, 1),    # Totalizer 3 assign
    # (3005, 2),    # Totalizer 3 mode, failure mode
    # (3008, 1),    # Totalizer 3 control
    # (3010, 2),    # Totalizer 3 value (was (3010, 4) incl. overflow)
    # (3012, 2),    # Totalizer 3 overflow
    #
    # Totalizer units
    # (4604, 2),    # Totalizer 1-2 units (was (4604, 3))
    # (4606, 1),    # Totalizer 3 unit
    #
    # Modbus config
    # (4910, 1),    # Bus address
    # (4912, 1),    # Baudrate
    # (4914, 2),    # Parity, Byte order
    # (4916, 2),    # Telegram delay
    # (4918, 1),    # Locking status
    # (4920, 1),    # Failure mode
    #
    # Flow velocity and pressure
    # (5085, 2),    # Flow velocity (was (5085, 4) incl. pressure)
    # (5087, 2),    # Pressure
    #
    # Sensor config
    # (5101, 1),    # Low flow cutoff
    # (5104, 2),    # Low flow cutoff off value
    # (5106, 1),    # Empty pipe detection
    #
    # Battery status
    # (9772, 2),    # Estimated battery lifetime
    # (9872, 2),    # Battery charge state
]


MODBUS_READ_SETTLE_SECS = 0.2
MODBUS_READ_ATTEMPTS = 5


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

    @property
    def volume_conversion_factor(self) -> float:
        """Factor to convert meter-native m³ values to the configured display unit.

        The meter reports volumes in m³; when the user configures litres we scale
        by 1000. Applies to both volume flow (m³/h → L/h) and totaliser (m³ → L).
        """
        return 1000.0 if self.config.units.value == "L" else 1.0

    def _to_display_volume(self, value):
        """Scale a meter-native m³ value into the configured display unit."""
        if value is None:
            return None
        return value * self.volume_conversion_factor

    async def setup(self):
        if self.use_modbus:
            # Initialize modbus state store
            # The meter returns 32-bit floats word-swapped (low word first);
            # confirmed on the wire (e.g. volume flow and totaliser only decode to
            # physically sensible values with this order, not ORDER_0123).
            self._modbus_state_store = ProMag800StateStore(byte_order=ByteOrder.ORDER_2301)
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
        elif self._my_ap_is_active():
            await self.eh_meter.update()
            correct_serial = self.ensure_serial_number()
            if not correct_serial:
                log.warning("Serial number mismatch, Sleeping Longer")
                await asyncio.sleep(25)
        else:
            log.info("WiFi rotator is on another meter's AP; skipping poll this cycle")

        self.ensure_meter_online()
        self.print_status()
        await self.update_tags()

    async def update_tags(self):
        await self.tags.volume_flow.set(self._to_display_volume(self.volume_flow))
        await self.tags.mass_flow.set(self.mass_flow)
        await self.tags.conductivity.set(self.conductivity)
        await self.tags.totaliser_1.set(self._to_display_volume(self.totaliser_1))
        # uiTimestamp expects milliseconds since epoch.
        await self.tags.last_read_time.set(int((time.time() - self.last_read_age) * 1000))
        await self.tags.meter_online.set(not self.meter_offline)
        await self.tags.meter_ok.set(not self.has_active_diagnostic)

    def _my_ap_is_active(self) -> bool:
        """Whether this meter's AP is the one the wifi-rotate app currently has connected.

        The E+H meter web server is single-session, so when several meter apps
        share one doovit behind a rotating WiFi connection, only the meter whose
        AP is currently active should be polled — otherwise they contend and all
        starve. Returns True (poll) when not coordinating with a rotator, or when
        the rotator's state can't be determined, so the app still works standalone.
        """
        rotator_key = self.config.wifi_rotator_app_key.value
        if not rotator_key:
            return True  # not coordinating; poll as normal (standalone use)

        active_ssid = self.get_tag("current_ssid", app_key=rotator_key)
        if not active_ssid:
            return True  # rotator not reporting yet / absent — fail open

        serial = self.config.eh_meter_serial_number.value
        if not serial:
            return True  # can't identify our AP without a serial — fail open

        # E+H AP SSIDs embed the meter serial suffix, e.g. the AP
        # "EH_Promag 400_D520000" corresponds to serial "X30CD520000".
        ssid_suffix = active_ssid.rsplit("_", 1)[-1]
        return serial.endswith(ssid_suffix)

    def ensure_serial_number(self):
        """Validate serial number (WiFi mode only)."""
        if self.use_modbus:
            return True
        if self.config.eh_meter_serial_number.value is None or self.config.eh_meter_serial_number.value == "":
            return True
        serial_number = self.eh_meter.get_value("Serial number")
        if serial_number is None:
            # Couldn't read the serial this cycle (e.g. a starved or partial read).
            # Don't wipe a possibly-valid cached reading — just skip confirmation.
            return True
        if serial_number != self.config.eh_meter_serial_number.value:
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
            values = await self._read_block(bus_id, modbus_id, start_address, num_registers)
            if values is not None:
                read_success = True
                # Key each value by its E+H register number so the state store
                # (which uses those numbers) finds it.
                for i, val in enumerate(values):
                    register_values[start_address + i] = val

        # Update the state store
        if read_success and register_values:
            self._modbus_state_store.update(register_values)
            self._last_modbus_update = time.time()
            log.debug(f"Modbus update successful, read {len(register_values)} registers")
        else:
            # Mark as uncontactable
            self._modbus_state_store.update(None)
            log.warning("Modbus read failed - no valid data received")

    async def _read_block(self, bus_id, modbus_id, start_address, num_registers):
        """Read one register block, with a settle delay + retries.

        Returns the list of register values, or None if every attempt failed.
        See MODBUS_REGISTER_BLOCKS for why the settle delay and retries are
        needed. ``start_address`` is the E+H register number; the wire read uses
        ``start_address - 1``.
        """
        for attempt in range(MODBUS_READ_ATTEMPTS):
            # Settle the line before each attempt (including retries - a retry
            # that fires immediately would just hit the same turnaround glitch).
            await asyncio.sleep(MODBUS_READ_SETTLE_SECS)
            try:
                values = await self.modbus_iface.read_registers(
                    bus_id=bus_id,
                    modbus_id=modbus_id,
                    start_address=start_address - 1,
                    num_registers=num_registers,
                    # doover modbus master register types: 3=input, 4=holding
                    # (the reverse of the Modbus FC numbers). The ProMag map is
                    # holding registers, so 4.
                    register_type=4,
                    # We own retries here (with a settle between); don't also let
                    # the master/pymodbus retry back-to-back without settling.
                    retries=0,
                )
                if values is not None:
                    return [values] if isinstance(values, int) else values
            except Exception as e:
                log.debug(
                    f"Read attempt {attempt + 1} for registers "
                    f"{start_address}-{start_address + num_registers - 1} failed: {e}"
                )
        log.warning(
            f"Failed to read registers {start_address}-{start_address + num_registers - 1} "
            f"after {MODBUS_READ_ATTEMPTS} attempts"
        )
        return None

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