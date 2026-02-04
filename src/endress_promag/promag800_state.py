"""
Endress+Hauser ProMag 800 Modbus State Interpreter

A module to interpret Modbus register data from an E+H ProMag 800
electromagnetic flow meter.

Register map based on GP01153DEN_0121 documentation.

Written for use with Doover modbus interface connections.
"""
import struct
import logging
from enum import IntEnum
from typing import Optional
from collections import deque

log = logging.getLogger(__name__)


# =============================================================================
# Enumerations for register value interpretation
# =============================================================================

class VolumeFlowUnit(IntEnum):
    CM3_S = 0
    CM3_MIN = 1
    CM3_H = 2
    CM3_D = 3
    DM3_S = 4
    DM3_MIN = 5
    DM3_H = 6
    DM3_D = 7
    M3_S = 8
    M3_MIN = 9
    M3_H = 10
    M3_D = 11
    ML_S = 12
    ML_MIN = 13
    ML_H = 14
    ML_D = 15
    L_S = 16
    L_MIN = 17
    L_H = 18
    L_D = 19
    HL_S = 20
    HL_MIN = 21
    HL_H = 22
    HL_D = 23
    ML_MEGA_S = 24
    ML_MEGA_MIN = 25
    ML_MEGA_H = 26
    ML_MEGA_D = 27
    AF_S = 32
    AF_MIN = 33
    AF_H = 34
    AF_D = 35
    FT3_S = 36
    FT3_MIN = 37
    FT3_H = 38
    FT3_D = 39
    GAL_US_S = 44
    GAL_US_MIN = 45
    GAL_US_H = 46
    GAL_US_D = 47
    MGAL_US_S = 48
    MGAL_US_MIN = 49
    MGAL_US_H = 50
    MGAL_US_D = 51
    GAL_IMP_S = 68
    GAL_IMP_MIN = 69
    GAL_IMP_H = 70
    GAL_IMP_D = 71


VOLUME_FLOW_UNIT_STRINGS = {
    VolumeFlowUnit.CM3_S: "cm³/s",
    VolumeFlowUnit.CM3_MIN: "cm³/min",
    VolumeFlowUnit.CM3_H: "cm³/h",
    VolumeFlowUnit.CM3_D: "cm³/d",
    VolumeFlowUnit.DM3_S: "dm³/s",
    VolumeFlowUnit.DM3_MIN: "dm³/min",
    VolumeFlowUnit.DM3_H: "dm³/h",
    VolumeFlowUnit.DM3_D: "dm³/d",
    VolumeFlowUnit.M3_S: "m³/s",
    VolumeFlowUnit.M3_MIN: "m³/min",
    VolumeFlowUnit.M3_H: "m³/h",
    VolumeFlowUnit.M3_D: "m³/d",
    VolumeFlowUnit.ML_S: "ml/s",
    VolumeFlowUnit.ML_MIN: "ml/min",
    VolumeFlowUnit.ML_H: "ml/h",
    VolumeFlowUnit.ML_D: "ml/d",
    VolumeFlowUnit.L_S: "l/s",
    VolumeFlowUnit.L_MIN: "l/min",
    VolumeFlowUnit.L_H: "l/h",
    VolumeFlowUnit.L_D: "l/d",
    VolumeFlowUnit.HL_S: "hl/s",
    VolumeFlowUnit.HL_MIN: "hl/min",
    VolumeFlowUnit.HL_H: "hl/h",
    VolumeFlowUnit.HL_D: "hl/d",
    VolumeFlowUnit.GAL_US_S: "gal(us)/s",
    VolumeFlowUnit.GAL_US_MIN: "gal(us)/min",
    VolumeFlowUnit.GAL_US_H: "gal(us)/h",
    VolumeFlowUnit.GAL_US_D: "gal(us)/d",
    VolumeFlowUnit.GAL_IMP_S: "gal(imp)/s",
    VolumeFlowUnit.GAL_IMP_MIN: "gal(imp)/min",
    VolumeFlowUnit.GAL_IMP_H: "gal(imp)/h",
    VolumeFlowUnit.GAL_IMP_D: "gal(imp)/d",
}


class VolumeUnit(IntEnum):
    CM3 = 0
    DM3 = 1
    M3 = 2
    ML = 3
    L = 4
    HL = 5
    ML_MEGA = 6
    AF = 8
    FT3 = 9
    FL_OZ_US = 10
    GAL_US = 11
    MGAL_US = 12
    GAL_IMP = 17
    MGAL_IMP = 18
    KGAL_US = 22
    MFT3 = 23
    NONE = 251


VOLUME_UNIT_STRINGS = {
    VolumeUnit.CM3: "cm³",
    VolumeUnit.DM3: "dm³",
    VolumeUnit.M3: "m³",
    VolumeUnit.ML: "ml",
    VolumeUnit.L: "l",
    VolumeUnit.HL: "hl",
    VolumeUnit.ML_MEGA: "Ml",
    VolumeUnit.AF: "af",
    VolumeUnit.FT3: "ft³",
    VolumeUnit.FL_OZ_US: "fl oz(us)",
    VolumeUnit.GAL_US: "gal(us)",
    VolumeUnit.MGAL_US: "Mgal(us)",
    VolumeUnit.GAL_IMP: "gal(imp)",
    VolumeUnit.MGAL_IMP: "Mgal(imp)",
    VolumeUnit.KGAL_US: "kgal(us)",
    VolumeUnit.MFT3: "Mft³",
    VolumeUnit.NONE: "",
}


class ConductivityUnit(IntEnum):
    MS_M = 1
    KS_M = 2
    S_M = 3
    S_CM = 4
    MS_M_2 = 5
    MS_CM = 6
    US_M = 7
    US_CM = 8
    US_MM = 9
    NS_CM = 10


CONDUCTIVITY_UNIT_STRINGS = {
    ConductivityUnit.MS_M: "MS/m",
    ConductivityUnit.KS_M: "kS/m",
    ConductivityUnit.S_M: "S/m",
    ConductivityUnit.S_CM: "S/cm",
    ConductivityUnit.MS_M_2: "mS/m",
    ConductivityUnit.MS_CM: "mS/cm",
    ConductivityUnit.US_M: "µS/m",
    ConductivityUnit.US_CM: "µS/cm",
    ConductivityUnit.US_MM: "µS/mm",
    ConductivityUnit.NS_CM: "nS/cm",
}


class TemperatureUnit(IntEnum):
    CELSIUS = 0
    KELVIN = 1
    FAHRENHEIT = 2
    RANKINE = 3


TEMPERATURE_UNIT_STRINGS = {
    TemperatureUnit.CELSIUS: "°C",
    TemperatureUnit.KELVIN: "K",
    TemperatureUnit.FAHRENHEIT: "°F",
    TemperatureUnit.RANKINE: "°R",
}


class PressureUnit(IntEnum):
    BAR = 0
    PSI_A = 1
    BAR_G = 2
    PSI_G = 3
    PA_A = 4
    KPA_A = 5
    MPA_A = 6
    PA_G = 7
    KPA_G = 8
    MPA_G = 9


PRESSURE_UNIT_STRINGS = {
    PressureUnit.BAR: "bar",
    PressureUnit.PSI_A: "psi a",
    PressureUnit.BAR_G: "bar g",
    PressureUnit.PSI_G: "psi g",
    PressureUnit.PA_A: "Pa a",
    PressureUnit.KPA_A: "kPa a",
    PressureUnit.MPA_A: "MPa a",
    PressureUnit.PA_G: "Pa g",
    PressureUnit.KPA_G: "kPa g",
    PressureUnit.MPA_G: "MPa g",
}


class TotalizerOperationMode(IntEnum):
    NET_FLOW_TOTAL = 0
    FORWARD_FLOW_TOTAL = 1
    REVERSE_FLOW_TOTAL = 2


class TotalizerControl(IntEnum):
    TOTALIZE = 0
    RESET_TOTALIZE = 1
    PRESET_HOLD = 2
    RESET_HOLD = 3
    HOLD = 5


class TotalizerFailureMode(IntEnum):
    STOP = 0
    ACTUAL_VALUE = 1
    LAST_VALID_VALUE = 2


class Baudrate(IntEnum):
    BAUD_1200 = 0
    BAUD_2400 = 1
    BAUD_4800 = 2
    BAUD_9600 = 3
    BAUD_19200 = 4
    BAUD_38400 = 5
    BAUD_57600 = 6
    BAUD_115200 = 7


BAUDRATE_VALUES = {
    Baudrate.BAUD_1200: 1200,
    Baudrate.BAUD_2400: 2400,
    Baudrate.BAUD_4800: 4800,
    Baudrate.BAUD_9600: 9600,
    Baudrate.BAUD_19200: 19200,
    Baudrate.BAUD_38400: 38400,
    Baudrate.BAUD_57600: 57600,
    Baudrate.BAUD_115200: 115200,
}


class Parity(IntEnum):
    EVEN = 0
    ODD = 1
    NONE_2_STOP = 2
    NONE_1_STOP = 3


class ByteOrder(IntEnum):
    ORDER_0123 = 0
    ORDER_3210 = 1
    ORDER_2301 = 2
    ORDER_1032 = 3

DEFAULT_BYTE_ORDER = ByteOrder.ORDER_1032

class BluetoothMode(IntEnum):
    ENABLE = 1
    ON_TOUCH = 2
    NOT_AVAILABLE = 4


class EmptyPipeDetection(IntEnum):
    OFF = 0
    ON = 1


class LowFlowCutoff(IntEnum):
    OFF = 0
    VOLUME_FLOW = 1


class LockingStatus(IntEnum):
    HARDWARE_LOCKED = 256
    TEMPORARILY_LOCKED = 512
    CT_ACTIVE_DEFINED = 2048
    CT_ACTIVE_ALL = 32768


class UserRole(IntEnum):
    OPERATOR = 0
    MAINTENANCE = 1
    SERVICE = 2
    PRODUCTION = 3
    DEVELOPMENT = 4


# =============================================================================
# Register address definitions
# =============================================================================

class ProMag800Registers:
    """
    Register addresses for the ProMag 800.
    Float registers span 2 addresses (4 bytes).
    String registers span multiple addresses depending on length.
    """
    # Measured values
    VOLUME_FLOW = 2009          # Float (2009-2010)
    CONDUCTIVITY = 2099         # Float (2099-2100)
    FLOW_VELOCITY = 5085        # Float (5085-5086)
    PRESSURE = 5087             # Float (5087-5088)

    # Totalizers (values and overflow counters)
    TOTALIZER_1_VALUE = 2610    # Float (2610-2611)
    TOTALIZER_1_OVERFLOW = 2612 # Float (2612-2613)
    TOTALIZER_2_VALUE = 2810    # Float (2810-2811)
    TOTALIZER_2_OVERFLOW = 2812 # Float (2812-2813)
    TOTALIZER_3_VALUE = 3010    # Float (3010-3011)
    TOTALIZER_3_OVERFLOW = 3012 # Float (3012-3013)

    # Totalizer settings
    TOTALIZER_1_ASSIGN = 2601   # Integer
    TOTALIZER_2_ASSIGN = 2801   # Integer
    TOTALIZER_3_ASSIGN = 3001   # Integer
    TOTALIZER_1_UNIT = 4604     # Integer
    TOTALIZER_2_UNIT = 4605     # Integer
    TOTALIZER_3_UNIT = 4606     # Integer
    TOTALIZER_1_MODE = 2605     # Integer
    TOTALIZER_2_MODE = 2805     # Integer
    TOTALIZER_3_MODE = 3005     # Integer
    TOTALIZER_1_CONTROL = 2608  # Integer
    TOTALIZER_2_CONTROL = 2808  # Integer
    TOTALIZER_3_CONTROL = 3008  # Integer
    TOTALIZER_1_FAILURE_MODE = 2606  # Integer
    TOTALIZER_2_FAILURE_MODE = 2806  # Integer
    TOTALIZER_3_FAILURE_MODE = 3006  # Integer
    RESET_ALL_TOTALIZERS = 2609      # Integer

    # Units configuration
    VOLUME_FLOW_UNIT = 2103     # Integer
    VOLUME_UNIT = 2104          # Integer
    CONDUCTIVITY_UNIT = 2121    # Integer
    TEMPERATURE_UNIT = 2109     # Integer
    PRESSURE_UNIT = 2130        # Integer

    # Power management
    ESTIMATED_BATTERY_LIFETIME = 9772    # Float (9772-9773)
    BATTERY_CHARGE_STATE = 9872          # Float (9872-9873)
    CONFIRM_BATTERY_REPLACEMENT = 31975  # Integer
    LOW_BATTERY_DIAGNOSTIC = 9663        # Float (9663-9664)
    CAPACITY_BATTERY_1 = 32880           # Float (32880-32881)
    CAPACITY_BATTERY_2 = 32882           # Float (32882-32883)

    # Diagnostics
    ACTUAL_DIAGNOSTICS = 2732            # Integer
    ACTUAL_DIAGNOSTICS_TIMESTAMP = 29726 # Integer
    PREVIOUS_DIAGNOSTICS = 2734          # Integer
    PREVIOUS_DIAGNOSTICS_TIMESTAMP = 29715  # Integer
    OPERATING_TIME_FROM_RESTART = 2624   # Integer
    OPERATING_TIME = 2631                # Integer
    DIAGNOSTICS_1 = 2736                 # Integer
    DIAGNOSTICS_1_TIMESTAMP = 29704      # Integer
    DIAGNOSTICS_2 = 2738                 # Integer
    DIAGNOSTICS_2_TIMESTAMP = 29693      # Integer
    DIAGNOSTICS_3 = 2740                 # Integer
    DIAGNOSTICS_3_TIMESTAMP = 29682      # Integer
    DIAGNOSTICS_4 = 2742                 # Integer
    DIAGNOSTICS_4_TIMESTAMP = 29671      # Integer
    DIAGNOSTICS_5 = 2744                 # Integer
    DIAGNOSTICS_5_TIMESTAMP = 29489      # Integer
    ALARM_DELAY = 6808                   # Float (6808-6809)

    # Modbus communication settings
    BUS_ADDRESS = 4910          # Integer
    BAUDRATE = 4912             # Integer
    PARITY = 4914               # Integer
    BYTE_ORDER = 4915           # Integer
    TELEGRAM_DELAY = 4916       # Float (4916-4917)
    MODBUS_FAILURE_MODE = 4920  # Integer
    FIELDBUS_WRITING_ACCESS = 6807  # Integer
    DEVICE_ID = 2547            # Integer
    DEVICE_REVISION = 4481      # Integer

    # Modbus data map (scan list)
    SCAN_LIST_REG_0 = 5001      # Integer

    # Device information
    DEVICE_TAG = 2026           # String (2026-2041, 32 chars)
    SERIAL_NUMBER = 7003        # String (7003-7008, 11 chars)
    FIRMWARE_VERSION = 7277     # String (7277-7280, 8 chars)
    DEVICE_NAME = 7263          # String (7263-7270, 16 chars)
    ORDER_CODE = 2058           # String (2058-2067, 20 chars)
    MANUFACTURER = 8001         # String (8001-8016, 32 chars)

    # Sensor configuration
    EMPTY_PIPE_DETECTION = 5106          # Integer
    EMPTY_PIPE_SWITCH_POINT = 2890       # Float (2890-2891)
    EMPTY_PIPE_ADJUST_VALUE = 2181       # Float (2181-2182)
    FULL_PIPE_ADJUST_VALUE = 2832        # Float (2832-2833)
    MEASURED_VALUE_EPD = 2298            # Float (2298-2299)
    LOW_FLOW_CUTOFF = 5101               # Integer
    LOW_FLOW_CUTOFF_ON_VALUE = 5138      # Float (5138-5139)
    LOW_FLOW_CUTOFF_OFF_VALUE = 5104     # Float (5104-5105)
    FLOW_DAMPING = 2274                  # Integer
    FLOW_DAMPING_TIME = 35954            # Float (35954-35955)
    CONDUCTIVITY_MEASUREMENT = 2268      # Integer
    CONDUCTIVITY_DAMPING_TIME = 35969    # Float (35969-35970)
    INSTALLATION_DIRECTION = 5501        # Integer
    INTEGRATION_TIME = 2260              # Float (2260-2261)
    MEASURING_PERIOD = 2852              # Float (2852-2853)
    MEASURING_INTERVAL_MODE = 9674       # Integer
    CURRENT_MEASURING_INTERVAL = 26573   # Float (26573-26574)
    MEASURING_INTERVAL_VALUE = 26274     # Float (26274-26275)

    # Calibration
    NOMINAL_DIAMETER = 2048              # String (2048-2057, 20 chars)
    CALIBRATION_FACTOR = 2313            # Float (2313-2314)
    ZERO_POINT = 2870                    # Float (2870-2871)
    CONDUCTIVITY_CAL_FACTOR = 19806      # Float (19806-19807)

    # System management
    LOCKING_STATUS = 4918               # Integer
    CONFIGURATION_COUNTER = 4818        # Integer
    DEVICE_RESET = 6817                 # Integer
    USER_ROLE = 2178                    # Integer
    ENTER_ACCESS_CODE = 2177            # Integer

    # Bluetooth
    BLUETOOTH = 27662                   # Integer

    # Date/time
    SET_DATE_TIME = 29652               # Integer
    TIME_FORMAT = 2150                  # Integer
    TIME_ZONE = 27339                   # Integer

    # Geolocation
    LOCATION_DESCRIPTION = 36061        # String (36061-36076, 32 chars)
    LONGITUDE = 26743                   # Float (26743-26744)
    LATITUDE = 26745                    # Float (26745-26746)
    ALTITUDE = 26748                    # Float (26748-26749)
    LOCATION_METHOD = 26747             # Integer


# =============================================================================
# Helper functions
# =============================================================================

def registers_to_float(reg_high: int, reg_low: int, byte_order: ByteOrder = DEFAULT_BYTE_ORDER) -> float:
    """
    Convert two 16-bit registers to a 32-bit IEEE 754 float.

    Args:
        reg_high: High word (first register)
        reg_low: Low word (second register)
        byte_order: Byte ordering mode from the device

    Returns:
        Decoded float value
    """
    if byte_order == ByteOrder.ORDER_0123:
        # Big-endian word order (default for E+H)
        packed = struct.pack('>HH', reg_high, reg_low)
    elif byte_order == ByteOrder.ORDER_3210:
        # Little-endian word order
        packed = struct.pack('<HH', reg_low, reg_high)
    elif byte_order == ByteOrder.ORDER_2301:
        # Big-endian byte swap
        packed = struct.pack('>HH', reg_low, reg_high)
    elif byte_order == ByteOrder.ORDER_1032:
        # Little-endian byte swap
        packed = struct.pack('<HH', reg_high, reg_low)
    else:
        packed = struct.pack('>HH', reg_high, reg_low)

    return struct.unpack('>f', packed)[0]


def float_to_registers(value: float, byte_order: ByteOrder = DEFAULT_BYTE_ORDER) -> tuple[int, int]:
    """
    Convert a 32-bit float to two 16-bit registers.

    Args:
        value: Float value to encode
        byte_order: Byte ordering mode for the device

    Returns:
        Tuple of (high_register, low_register)
    """
    packed = struct.pack('>f', value)
    reg_high, reg_low = struct.unpack('>HH', packed)

    if byte_order == ByteOrder.ORDER_0123:
        return reg_high, reg_low
    elif byte_order == ByteOrder.ORDER_3210:
        return reg_low, reg_high
    elif byte_order == ByteOrder.ORDER_2301:
        return reg_low, reg_high
    elif byte_order == ByteOrder.ORDER_1032:
        return reg_high, reg_low
    else:
        return reg_high, reg_low


def registers_to_string(registers: list[int]) -> str:
    """
    Convert a list of 16-bit registers to a string.
    Each register contains 2 ASCII characters.

    Args:
        registers: List of 16-bit register values

    Returns:
        Decoded string with null characters removed
    """
    chars = []
    for reg in registers:
        high_byte = (reg >> 8) & 0xFF
        low_byte = reg & 0xFF
        if high_byte != 0:
            chars.append(chr(high_byte))
        if low_byte != 0:
            chars.append(chr(low_byte))
    return ''.join(chars).strip('\x00')


def string_to_registers(text: str, length: int) -> list[int]:
    """
    Convert a string to a list of 16-bit registers.

    Args:
        text: String to encode
        length: Number of registers to fill

    Returns:
        List of 16-bit register values
    """
    # Pad string to fill all registers
    text = text.ljust(length * 2, '\x00')
    registers = []
    for i in range(0, len(text), 2):
        high_byte = ord(text[i]) if i < len(text) else 0
        low_byte = ord(text[i + 1]) if i + 1 < len(text) else 0
        registers.append((high_byte << 8) | low_byte)
    return registers[:length]


# =============================================================================
# State Record Class
# =============================================================================

class ProMag800StateRecord:
    """
    Interprets a snapshot of Modbus register values from a ProMag 800.

    This class receives a dictionary mapping register addresses to values
    and provides property-based access to interpreted meter data.
    """

    def __init__(self, register_values: dict[int, int], byte_order: ByteOrder = DEFAULT_BYTE_ORDER):
        """
        Initialize state record with raw register values.

        Args:
            register_values: Dictionary mapping register address to value
            byte_order: Byte ordering for float interpretation
        """
        self._registers = register_values
        self._byte_order = byte_order

    def _get_register(self, address: int, default: int = 0) -> int:
        """Get a single register value."""
        return self._registers.get(address, default)

    def _get_float(self, address: int) -> Optional[float]:
        """Get a float value from two consecutive registers."""
        reg_high = self._registers.get(address)
        reg_low = self._registers.get(address + 1)
        if reg_high is None or reg_low is None:
            return None
        return registers_to_float(reg_high, reg_low, self._byte_order)

    def _get_string(self, start_address: int, num_registers: int) -> Optional[str]:
        """Get a string value from consecutive registers."""
        registers = []
        for i in range(num_registers):
            reg = self._registers.get(start_address + i)
            if reg is None:
                return None
            registers.append(reg)
        return registers_to_string(registers)

    # =========================================================================
    # Measured Values
    # =========================================================================

    @property
    def volume_flow(self) -> Optional[float]:
        """Current volume flow rate."""
        return self._get_float(ProMag800Registers.VOLUME_FLOW)

    @property
    def conductivity(self) -> Optional[float]:
        """Current conductivity measurement."""
        return self._get_float(ProMag800Registers.CONDUCTIVITY)

    @property
    def flow_velocity(self) -> Optional[float]:
        """Current flow velocity."""
        return self._get_float(ProMag800Registers.FLOW_VELOCITY)

    @property
    def pressure(self) -> Optional[float]:
        """Current pressure measurement."""
        return self._get_float(ProMag800Registers.PRESSURE)

    # =========================================================================
    # Totalizers
    # =========================================================================

    @property
    def totalizer_1_value(self) -> Optional[float]:
        """Totalizer 1 current value."""
        return self._get_float(ProMag800Registers.TOTALIZER_1_VALUE)

    @property
    def totalizer_1_overflow(self) -> Optional[float]:
        """Totalizer 1 overflow counter."""
        return self._get_float(ProMag800Registers.TOTALIZER_1_OVERFLOW)

    @property
    def totalizer_2_value(self) -> Optional[float]:
        """Totalizer 2 current value."""
        return self._get_float(ProMag800Registers.TOTALIZER_2_VALUE)

    @property
    def totalizer_2_overflow(self) -> Optional[float]:
        """Totalizer 2 overflow counter."""
        return self._get_float(ProMag800Registers.TOTALIZER_2_OVERFLOW)

    @property
    def totalizer_3_value(self) -> Optional[float]:
        """Totalizer 3 current value."""
        return self._get_float(ProMag800Registers.TOTALIZER_3_VALUE)

    @property
    def totalizer_3_overflow(self) -> Optional[float]:
        """Totalizer 3 overflow counter."""
        return self._get_float(ProMag800Registers.TOTALIZER_3_OVERFLOW)

    def get_totalizer_value(self, index: int) -> Optional[float]:
        """Get totalizer value by index (1-3)."""
        if index == 1:
            return self.totalizer_1_value
        elif index == 2:
            return self.totalizer_2_value
        elif index == 3:
            return self.totalizer_3_value
        return None

    def get_totalizer_overflow(self, index: int) -> Optional[float]:
        """Get totalizer overflow by index (1-3)."""
        if index == 1:
            return self.totalizer_1_overflow
        elif index == 2:
            return self.totalizer_2_overflow
        elif index == 3:
            return self.totalizer_3_overflow
        return None

    @property
    def totalizer_1_unit(self) -> Optional[VolumeUnit]:
        """Totalizer 1 unit."""
        val = self._get_register(ProMag800Registers.TOTALIZER_1_UNIT)
        try:
            return VolumeUnit(val)
        except ValueError:
            return None

    @property
    def totalizer_2_unit(self) -> Optional[VolumeUnit]:
        """Totalizer 2 unit."""
        val = self._get_register(ProMag800Registers.TOTALIZER_2_UNIT)
        try:
            return VolumeUnit(val)
        except ValueError:
            return None

    @property
    def totalizer_3_unit(self) -> Optional[VolumeUnit]:
        """Totalizer 3 unit."""
        val = self._get_register(ProMag800Registers.TOTALIZER_3_UNIT)
        try:
            return VolumeUnit(val)
        except ValueError:
            return None

    @property
    def totalizer_1_mode(self) -> Optional[TotalizerOperationMode]:
        """Totalizer 1 operation mode."""
        val = self._get_register(ProMag800Registers.TOTALIZER_1_MODE)
        try:
            return TotalizerOperationMode(val)
        except ValueError:
            return None

    @property
    def totalizer_2_mode(self) -> Optional[TotalizerOperationMode]:
        """Totalizer 2 operation mode."""
        val = self._get_register(ProMag800Registers.TOTALIZER_2_MODE)
        try:
            return TotalizerOperationMode(val)
        except ValueError:
            return None

    @property
    def totalizer_3_mode(self) -> Optional[TotalizerOperationMode]:
        """Totalizer 3 operation mode."""
        val = self._get_register(ProMag800Registers.TOTALIZER_3_MODE)
        try:
            return TotalizerOperationMode(val)
        except ValueError:
            return None

    # =========================================================================
    # Units
    # =========================================================================

    @property
    def volume_flow_unit(self) -> Optional[VolumeFlowUnit]:
        """Current volume flow unit."""
        val = self._get_register(ProMag800Registers.VOLUME_FLOW_UNIT)
        try:
            return VolumeFlowUnit(val)
        except ValueError:
            return None

    @property
    def volume_flow_unit_string(self) -> str:
        """Current volume flow unit as string."""
        unit = self.volume_flow_unit
        return VOLUME_FLOW_UNIT_STRINGS.get(unit, "") if unit else ""

    @property
    def volume_unit(self) -> Optional[VolumeUnit]:
        """Current volume unit (for totalizers)."""
        val = self._get_register(ProMag800Registers.VOLUME_UNIT)
        try:
            return VolumeUnit(val)
        except ValueError:
            return None

    @property
    def volume_unit_string(self) -> str:
        """Current volume unit as string."""
        unit = self.volume_unit
        return VOLUME_UNIT_STRINGS.get(unit, "") if unit else ""

    @property
    def conductivity_unit(self) -> Optional[ConductivityUnit]:
        """Current conductivity unit."""
        val = self._get_register(ProMag800Registers.CONDUCTIVITY_UNIT)
        try:
            return ConductivityUnit(val)
        except ValueError:
            return None

    @property
    def conductivity_unit_string(self) -> str:
        """Current conductivity unit as string."""
        unit = self.conductivity_unit
        return CONDUCTIVITY_UNIT_STRINGS.get(unit, "") if unit else ""

    @property
    def temperature_unit(self) -> Optional[TemperatureUnit]:
        """Current temperature unit."""
        val = self._get_register(ProMag800Registers.TEMPERATURE_UNIT)
        try:
            return TemperatureUnit(val)
        except ValueError:
            return None

    @property
    def temperature_unit_string(self) -> str:
        """Current temperature unit as string."""
        unit = self.temperature_unit
        return TEMPERATURE_UNIT_STRINGS.get(unit, "") if unit else ""

    @property
    def pressure_unit(self) -> Optional[PressureUnit]:
        """Current pressure unit."""
        val = self._get_register(ProMag800Registers.PRESSURE_UNIT)
        try:
            return PressureUnit(val)
        except ValueError:
            return None

    @property
    def pressure_unit_string(self) -> str:
        """Current pressure unit as string."""
        unit = self.pressure_unit
        return PRESSURE_UNIT_STRINGS.get(unit, "") if unit else ""

    # =========================================================================
    # Battery / Power
    # =========================================================================

    @property
    def estimated_battery_lifetime(self) -> Optional[float]:
        """Estimated remaining battery lifetime."""
        return self._get_float(ProMag800Registers.ESTIMATED_BATTERY_LIFETIME)

    @property
    def battery_charge_state(self) -> Optional[float]:
        """Battery charge state (0-100%)."""
        return self._get_float(ProMag800Registers.BATTERY_CHARGE_STATE)

    @property
    def battery_1_capacity(self) -> Optional[float]:
        """Battery 1 capacity."""
        return self._get_float(ProMag800Registers.CAPACITY_BATTERY_1)

    @property
    def battery_2_capacity(self) -> Optional[float]:
        """Battery 2 capacity."""
        return self._get_float(ProMag800Registers.CAPACITY_BATTERY_2)

    @property
    def low_battery_diagnostic_threshold(self) -> Optional[float]:
        """Low battery diagnostic message threshold."""
        return self._get_float(ProMag800Registers.LOW_BATTERY_DIAGNOSTIC)

    # =========================================================================
    # Diagnostics
    # =========================================================================

    @property
    def actual_diagnostics(self) -> int:
        """Current diagnostic code."""
        return self._get_register(ProMag800Registers.ACTUAL_DIAGNOSTICS)

    @property
    def actual_diagnostics_timestamp(self) -> int:
        """Timestamp of current diagnostic."""
        return self._get_register(ProMag800Registers.ACTUAL_DIAGNOSTICS_TIMESTAMP)

    @property
    def previous_diagnostics(self) -> int:
        """Previous diagnostic code."""
        return self._get_register(ProMag800Registers.PREVIOUS_DIAGNOSTICS)

    @property
    def operating_time(self) -> int:
        """Total operating time."""
        return self._get_register(ProMag800Registers.OPERATING_TIME)

    @property
    def operating_time_from_restart(self) -> int:
        """Operating time since last restart."""
        return self._get_register(ProMag800Registers.OPERATING_TIME_FROM_RESTART)

    @property
    def diagnostics_list(self) -> list[dict]:
        """Get list of diagnostic codes with timestamps."""
        diag_regs = [
            (ProMag800Registers.DIAGNOSTICS_1, ProMag800Registers.DIAGNOSTICS_1_TIMESTAMP),
            (ProMag800Registers.DIAGNOSTICS_2, ProMag800Registers.DIAGNOSTICS_2_TIMESTAMP),
            (ProMag800Registers.DIAGNOSTICS_3, ProMag800Registers.DIAGNOSTICS_3_TIMESTAMP),
            (ProMag800Registers.DIAGNOSTICS_4, ProMag800Registers.DIAGNOSTICS_4_TIMESTAMP),
            (ProMag800Registers.DIAGNOSTICS_5, ProMag800Registers.DIAGNOSTICS_5_TIMESTAMP),
        ]
        result = []
        for code_reg, ts_reg in diag_regs:
            code = self._get_register(code_reg)
            if code != 0:
                result.append({
                    'code': code,
                    'timestamp': self._get_register(ts_reg)
                })
        return result

    @property
    def has_active_diagnostic(self) -> bool:
        """Check if there is an active diagnostic code."""
        return self.actual_diagnostics != 0

    @property
    def alarm_delay(self) -> Optional[float]:
        """Alarm delay setting (0-60s)."""
        return self._get_float(ProMag800Registers.ALARM_DELAY)

    # =========================================================================
    # Modbus Communication Settings
    # =========================================================================

    @property
    def bus_address(self) -> int:
        """Modbus bus address (1-247)."""
        return self._get_register(ProMag800Registers.BUS_ADDRESS)

    @property
    def baudrate(self) -> Optional[Baudrate]:
        """Modbus baudrate setting."""
        val = self._get_register(ProMag800Registers.BAUDRATE)
        try:
            return Baudrate(val)
        except ValueError:
            return None

    @property
    def baudrate_value(self) -> int:
        """Modbus baudrate as integer value."""
        br = self.baudrate
        return BAUDRATE_VALUES.get(br, 0) if br else 0

    @property
    def parity(self) -> Optional[Parity]:
        """Modbus parity setting."""
        val = self._get_register(ProMag800Registers.PARITY)
        try:
            return Parity(val)
        except ValueError:
            return None

    @property
    def byte_order(self) -> Optional[ByteOrder]:
        """Modbus byte order setting."""
        val = self._get_register(ProMag800Registers.BYTE_ORDER)
        try:
            return ByteOrder(val)
        except ValueError:
            return None

    @property
    def telegram_delay(self) -> Optional[float]:
        """Modbus telegram delay (0-100ms)."""
        return self._get_float(ProMag800Registers.TELEGRAM_DELAY)

    @property
    def device_id(self) -> int:
        """Modbus device ID."""
        return self._get_register(ProMag800Registers.DEVICE_ID)

    @property
    def device_revision(self) -> int:
        """Device revision number."""
        return self._get_register(ProMag800Registers.DEVICE_REVISION)

    @property
    def fieldbus_writing_access(self) -> bool:
        """Whether fieldbus writing is enabled (False = Read+Write, True = Read Only)."""
        return self._get_register(ProMag800Registers.FIELDBUS_WRITING_ACCESS) == 1

    # =========================================================================
    # Device Information
    # =========================================================================

    @property
    def device_tag(self) -> Optional[str]:
        """Device tag (user-defined name)."""
        return self._get_string(ProMag800Registers.DEVICE_TAG, 16)

    @property
    def serial_number(self) -> Optional[str]:
        """Device serial number."""
        return self._get_string(ProMag800Registers.SERIAL_NUMBER, 6)

    @property
    def firmware_version(self) -> Optional[str]:
        """Firmware version string."""
        return self._get_string(ProMag800Registers.FIRMWARE_VERSION, 4)

    @property
    def device_name(self) -> Optional[str]:
        """Device name."""
        return self._get_string(ProMag800Registers.DEVICE_NAME, 8)

    @property
    def order_code(self) -> Optional[str]:
        """Order code."""
        return self._get_string(ProMag800Registers.ORDER_CODE, 10)

    @property
    def manufacturer(self) -> Optional[str]:
        """Manufacturer name."""
        return self._get_string(ProMag800Registers.MANUFACTURER, 16)

    # =========================================================================
    # Sensor Configuration
    # =========================================================================

    @property
    def empty_pipe_detection_enabled(self) -> bool:
        """Whether empty pipe detection is enabled."""
        return self._get_register(ProMag800Registers.EMPTY_PIPE_DETECTION) == 1

    @property
    def empty_pipe_switch_point(self) -> Optional[float]:
        """Empty pipe detection switch point (0-100%)."""
        return self._get_float(ProMag800Registers.EMPTY_PIPE_SWITCH_POINT)

    @property
    def measured_value_epd(self) -> Optional[float]:
        """Current empty pipe detection measured value."""
        return self._get_float(ProMag800Registers.MEASURED_VALUE_EPD)

    @property
    def low_flow_cutoff_enabled(self) -> bool:
        """Whether low flow cutoff is enabled."""
        return self._get_register(ProMag800Registers.LOW_FLOW_CUTOFF) == 1

    @property
    def low_flow_cutoff_on_value(self) -> Optional[float]:
        """Low flow cutoff on value."""
        return self._get_float(ProMag800Registers.LOW_FLOW_CUTOFF_ON_VALUE)

    @property
    def low_flow_cutoff_off_value(self) -> Optional[float]:
        """Low flow cutoff off value (0-100%)."""
        return self._get_float(ProMag800Registers.LOW_FLOW_CUTOFF_OFF_VALUE)

    @property
    def flow_damping(self) -> int:
        """Flow damping level (0-15)."""
        return self._get_register(ProMag800Registers.FLOW_DAMPING)

    @property
    def flow_damping_time(self) -> Optional[float]:
        """Flow damping time (0-99.9s)."""
        return self._get_float(ProMag800Registers.FLOW_DAMPING_TIME)

    @property
    def conductivity_measurement_enabled(self) -> bool:
        """Whether conductivity measurement is enabled."""
        return self._get_register(ProMag800Registers.CONDUCTIVITY_MEASUREMENT) == 1

    @property
    def conductivity_damping_time(self) -> Optional[float]:
        """Conductivity damping time (0-999.9s)."""
        return self._get_float(ProMag800Registers.CONDUCTIVITY_DAMPING_TIME)

    @property
    def installation_direction_forward(self) -> bool:
        """True if installation direction is forward flow."""
        return self._get_register(ProMag800Registers.INSTALLATION_DIRECTION) == 0

    @property
    def integration_time(self) -> Optional[float]:
        """Integration time (1-65ms)."""
        return self._get_float(ProMag800Registers.INTEGRATION_TIME)

    @property
    def measuring_period(self) -> Optional[float]:
        """Measuring period (0-1000ms)."""
        return self._get_float(ProMag800Registers.MEASURING_PERIOD)

    @property
    def current_measuring_interval(self) -> Optional[float]:
        """Current measuring interval."""
        return self._get_float(ProMag800Registers.CURRENT_MEASURING_INTERVAL)

    # =========================================================================
    # Calibration
    # =========================================================================

    @property
    def nominal_diameter(self) -> Optional[str]:
        """Nominal pipe diameter."""
        return self._get_string(ProMag800Registers.NOMINAL_DIAMETER, 10)

    @property
    def calibration_factor(self) -> Optional[float]:
        """Calibration factor."""
        return self._get_float(ProMag800Registers.CALIBRATION_FACTOR)

    @property
    def zero_point(self) -> Optional[float]:
        """Zero point offset."""
        return self._get_float(ProMag800Registers.ZERO_POINT)

    @property
    def conductivity_calibration_factor(self) -> Optional[float]:
        """Conductivity calibration factor (0.01-10000)."""
        return self._get_float(ProMag800Registers.CONDUCTIVITY_CAL_FACTOR)

    # =========================================================================
    # System Status
    # =========================================================================

    @property
    def locking_status(self) -> int:
        """Device locking status."""
        return self._get_register(ProMag800Registers.LOCKING_STATUS)

    @property
    def is_hardware_locked(self) -> bool:
        """Check if device is hardware locked."""
        return (self.locking_status & LockingStatus.HARDWARE_LOCKED) != 0

    @property
    def is_temporarily_locked(self) -> bool:
        """Check if device is temporarily locked."""
        return (self.locking_status & LockingStatus.TEMPORARILY_LOCKED) != 0

    @property
    def configuration_counter(self) -> int:
        """Configuration change counter."""
        return self._get_register(ProMag800Registers.CONFIGURATION_COUNTER)

    @property
    def user_role(self) -> Optional[UserRole]:
        """Current user role."""
        val = self._get_register(ProMag800Registers.USER_ROLE)
        try:
            return UserRole(val)
        except ValueError:
            return None

    # =========================================================================
    # Bluetooth
    # =========================================================================

    @property
    def bluetooth_mode(self) -> Optional[BluetoothMode]:
        """Bluetooth configuration mode."""
        val = self._get_register(ProMag800Registers.BLUETOOTH)
        try:
            return BluetoothMode(val)
        except ValueError:
            return None

    @property
    def bluetooth_enabled(self) -> bool:
        """Check if Bluetooth is enabled."""
        mode = self.bluetooth_mode
        return mode == BluetoothMode.ENABLE if mode else False

    # =========================================================================
    # Geolocation
    # =========================================================================

    @property
    def location_description(self) -> Optional[str]:
        """Location description string."""
        return self._get_string(ProMag800Registers.LOCATION_DESCRIPTION, 16)

    @property
    def longitude(self) -> Optional[float]:
        """Longitude (-180 to 180 degrees)."""
        return self._get_float(ProMag800Registers.LONGITUDE)

    @property
    def latitude(self) -> Optional[float]:
        """Latitude (-90 to 90 degrees)."""
        return self._get_float(ProMag800Registers.LATITUDE)

    @property
    def altitude(self) -> Optional[float]:
        """Altitude."""
        return self._get_float(ProMag800Registers.ALTITUDE)

    # =========================================================================
    # Convenience Methods
    # =========================================================================

    def to_dict(self) -> dict:
        """Export all measured values and status to a dictionary."""
        return {
            'volume_flow': self.volume_flow,
            'volume_flow_unit': self.volume_flow_unit_string,
            'conductivity': self.conductivity,
            'conductivity_unit': self.conductivity_unit_string,
            'flow_velocity': self.flow_velocity,
            'pressure': self.pressure,
            'pressure_unit': self.pressure_unit_string,
            'totalizer_1': self.totalizer_1_value,
            'totalizer_1_overflow': self.totalizer_1_overflow,
            'totalizer_2': self.totalizer_2_value,
            'totalizer_2_overflow': self.totalizer_2_overflow,
            'totalizer_3': self.totalizer_3_value,
            'totalizer_3_overflow': self.totalizer_3_overflow,
            'battery_charge_state': self.battery_charge_state,
            'estimated_battery_lifetime': self.estimated_battery_lifetime,
            'actual_diagnostics': self.actual_diagnostics,
            'has_active_diagnostic': self.has_active_diagnostic,
            'operating_time': self.operating_time,
            'device_tag': self.device_tag,
            'serial_number': self.serial_number,
            'firmware_version': self.firmware_version,
            'empty_pipe_detection': self.empty_pipe_detection_enabled,
            'low_flow_cutoff': self.low_flow_cutoff_enabled,
        }


# =============================================================================
# State Store Class (maintains history)
# =============================================================================

class ProMag800StateStore:
    """
    Maintains a history of ProMag 800 state records.

    Similar to K37StateStore, this class tracks contactability and
    provides access to current and historical state data.
    """

    def __init__(self, byte_order: ByteOrder = DEFAULT_BYTE_ORDER, max_records: int = 100):
        """
        Initialize the state store.

        Args:
            byte_order: Byte ordering for float interpretation
            max_records: Maximum number of state records to keep
        """
        self._byte_order = byte_order
        self._states: deque[ProMag800StateRecord] = deque(maxlen=max_records)
        self.is_contactable = False
        self._became_uncontactable_at: Optional[float] = None
        self._iters_uncontactable = 0

    @property
    def num_records(self) -> int:
        """Number of state records in history."""
        return len(self._states)

    @property
    def state(self) -> Optional[ProMag800StateRecord]:
        """Most recent state record."""
        return self._states[0] if self._states else None

    @property
    def states(self) -> deque[ProMag800StateRecord]:
        """Access to state history."""
        return self._states

    def add(self, record: ProMag800StateRecord):
        """Add a new state record."""
        self._states.appendleft(record)

    def update_contactability(self, is_contactable: bool):
        """Update contactability status."""
        import time
        if is_contactable:
            self.is_contactable = True
            self._became_uncontactable_at = None
            self._iters_uncontactable = 0
        else:
            if self.is_contactable:
                self.is_contactable = False
                self._became_uncontactable_at = time.time()
            self._iters_uncontactable += 1

    def update(self, register_values: Optional[dict[int, int]]):
        """
        Update state with new register values.

        Args:
            register_values: Dictionary of register address to value, or None if communication failed
        """
        self.update_contactability(register_values is not None)
        if register_values:
            self.add(ProMag800StateRecord(register_values, self._byte_order))

    def check_lost_comms(self, timeout_seconds: float = 30, min_iterations: int = 3) -> bool:
        """
        Check if communication has been lost.

        Args:
            timeout_seconds: Time threshold for lost communication
            min_iterations: Minimum failed iterations before declaring lost

        Returns:
            True if communication is considered lost
        """
        import time
        if self.is_contactable:
            return False

        if self._became_uncontactable_at is None:
            return False

        time_uncontactable = time.time() - self._became_uncontactable_at
        return time_uncontactable > timeout_seconds and self._iters_uncontactable >= min_iterations

    # Proxy common properties to current state
    def __getattr__(self, name):
        """Proxy attribute access to current state record."""
        if self.state is not None:
            return getattr(self.state, name)
        return None


# =============================================================================
# Write Command Builder
# =============================================================================

class ProMag800WriteCommands:
    """
    Helper class to build Modbus write commands for the ProMag 800.

    Returns dictionaries mapping register addresses to values,
    suitable for use with a Doover modbus interface.
    """

    def __init__(self, byte_order: ByteOrder = DEFAULT_BYTE_ORDER):
        self._byte_order = byte_order

    def reset_totalizer(self, index: int) -> dict[int, int]:
        """
        Generate command to reset a specific totalizer.

        Args:
            index: Totalizer index (1-3)

        Returns:
            Register values to write
        """
        control_regs = {
            1: ProMag800Registers.TOTALIZER_1_CONTROL,
            2: ProMag800Registers.TOTALIZER_2_CONTROL,
            3: ProMag800Registers.TOTALIZER_3_CONTROL,
        }
        if index not in control_regs:
            raise ValueError(f"Invalid totalizer index: {index}")
        return {control_regs[index]: TotalizerControl.RESET_TOTALIZE}

    def reset_all_totalizers(self) -> dict[int, int]:
        """Generate command to reset all totalizers."""
        return {ProMag800Registers.RESET_ALL_TOTALIZERS: 1}

    def set_totalizer_mode(self, index: int, mode: TotalizerOperationMode) -> dict[int, int]:
        """
        Set totalizer operation mode.

        Args:
            index: Totalizer index (1-3)
            mode: Operation mode (net, forward, reverse)
        """
        mode_regs = {
            1: ProMag800Registers.TOTALIZER_1_MODE,
            2: ProMag800Registers.TOTALIZER_2_MODE,
            3: ProMag800Registers.TOTALIZER_3_MODE,
        }
        if index not in mode_regs:
            raise ValueError(f"Invalid totalizer index: {index}")
        return {mode_regs[index]: mode}

    def set_volume_flow_unit(self, unit: VolumeFlowUnit) -> dict[int, int]:
        """Set the volume flow unit."""
        return {ProMag800Registers.VOLUME_FLOW_UNIT: unit}

    def set_volume_unit(self, unit: VolumeUnit) -> dict[int, int]:
        """Set the volume unit (for totalizers)."""
        return {ProMag800Registers.VOLUME_UNIT: unit}

    def set_conductivity_unit(self, unit: ConductivityUnit) -> dict[int, int]:
        """Set the conductivity unit."""
        return {ProMag800Registers.CONDUCTIVITY_UNIT: unit}

    def set_temperature_unit(self, unit: TemperatureUnit) -> dict[int, int]:
        """Set the temperature unit."""
        return {ProMag800Registers.TEMPERATURE_UNIT: unit}

    def set_pressure_unit(self, unit: PressureUnit) -> dict[int, int]:
        """Set the pressure unit."""
        return {ProMag800Registers.PRESSURE_UNIT: unit}

    def set_empty_pipe_detection(self, enabled: bool) -> dict[int, int]:
        """Enable or disable empty pipe detection."""
        return {ProMag800Registers.EMPTY_PIPE_DETECTION: 1 if enabled else 0}

    def set_low_flow_cutoff(self, enabled: bool) -> dict[int, int]:
        """Enable or disable low flow cutoff."""
        return {ProMag800Registers.LOW_FLOW_CUTOFF: 1 if enabled else 0}

    def set_low_flow_cutoff_on_value(self, value: float) -> dict[int, int]:
        """Set low flow cutoff on value."""
        reg_high, reg_low = float_to_registers(value, self._byte_order)
        return {
            ProMag800Registers.LOW_FLOW_CUTOFF_ON_VALUE: reg_high,
            ProMag800Registers.LOW_FLOW_CUTOFF_ON_VALUE + 1: reg_low,
        }

    def set_flow_damping(self, level: int) -> dict[int, int]:
        """Set flow damping level (0-15)."""
        if not 0 <= level <= 15:
            raise ValueError("Flow damping must be 0-15")
        return {ProMag800Registers.FLOW_DAMPING: level}

    def set_device_tag(self, tag: str) -> dict[int, int]:
        """Set the device tag (max 32 characters)."""
        registers = string_to_registers(tag[:32], 16)
        result = {}
        for i, val in enumerate(registers):
            result[ProMag800Registers.DEVICE_TAG + i] = val
        return result

    def set_bus_address(self, address: int) -> dict[int, int]:
        """Set Modbus bus address (1-247)."""
        if not 1 <= address <= 247:
            raise ValueError("Bus address must be 1-247")
        return {ProMag800Registers.BUS_ADDRESS: address}

    def set_baudrate(self, baudrate: Baudrate) -> dict[int, int]:
        """Set Modbus baudrate."""
        return {ProMag800Registers.BAUDRATE: baudrate}

    def set_parity(self, parity: Parity) -> dict[int, int]:
        """Set Modbus parity."""
        return {ProMag800Registers.PARITY: parity}

    def set_byte_order(self, order: ByteOrder) -> dict[int, int]:
        """Set Modbus byte order."""
        return {ProMag800Registers.BYTE_ORDER: order}

    def set_bluetooth(self, mode: BluetoothMode) -> dict[int, int]:
        """Set Bluetooth mode."""
        return {ProMag800Registers.BLUETOOTH: mode}

    def enter_access_code(self, code: int) -> dict[int, int]:
        """Enter access code (0-9999)."""
        if not 0 <= code <= 9999:
            raise ValueError("Access code must be 0-9999")
        return {ProMag800Registers.ENTER_ACCESS_CODE: code}

    def restart_device(self) -> dict[int, int]:
        """Restart the device."""
        return {ProMag800Registers.DEVICE_RESET: 1}

    def factory_reset(self) -> dict[int, int]:
        """Reset device to factory settings."""
        return {ProMag800Registers.DEVICE_RESET: 2}

    def confirm_battery_replacement(self, battery_index: int) -> dict[int, int]:
        """
        Confirm battery replacement.

        Args:
            battery_index: 1 or 2
        """
        if battery_index == 1:
            return {ProMag800Registers.CONFIRM_BATTERY_REPLACEMENT: 71}
        elif battery_index == 2:
            return {ProMag800Registers.CONFIRM_BATTERY_REPLACEMENT: 72}
        else:
            raise ValueError("Battery index must be 1 or 2")


# =============================================================================
# Register Read List Builder
# =============================================================================

def get_measured_value_registers() -> list[int]:
    """Get list of registers for measured values."""
    return [
        ProMag800Registers.VOLUME_FLOW,
        ProMag800Registers.VOLUME_FLOW + 1,
        ProMag800Registers.CONDUCTIVITY,
        ProMag800Registers.CONDUCTIVITY + 1,
        ProMag800Registers.FLOW_VELOCITY,
        ProMag800Registers.FLOW_VELOCITY + 1,
        ProMag800Registers.PRESSURE,
        ProMag800Registers.PRESSURE + 1,
    ]


def get_totalizer_registers() -> list[int]:
    """Get list of registers for all totalizers."""
    return [
        ProMag800Registers.TOTALIZER_1_VALUE,
        ProMag800Registers.TOTALIZER_1_VALUE + 1,
        ProMag800Registers.TOTALIZER_1_OVERFLOW,
        ProMag800Registers.TOTALIZER_1_OVERFLOW + 1,
        ProMag800Registers.TOTALIZER_2_VALUE,
        ProMag800Registers.TOTALIZER_2_VALUE + 1,
        ProMag800Registers.TOTALIZER_2_OVERFLOW,
        ProMag800Registers.TOTALIZER_2_OVERFLOW + 1,
        ProMag800Registers.TOTALIZER_3_VALUE,
        ProMag800Registers.TOTALIZER_3_VALUE + 1,
        ProMag800Registers.TOTALIZER_3_OVERFLOW,
        ProMag800Registers.TOTALIZER_3_OVERFLOW + 1,
        ProMag800Registers.TOTALIZER_1_UNIT,
        ProMag800Registers.TOTALIZER_2_UNIT,
        ProMag800Registers.TOTALIZER_3_UNIT,
        ProMag800Registers.TOTALIZER_1_MODE,
        ProMag800Registers.TOTALIZER_2_MODE,
        ProMag800Registers.TOTALIZER_3_MODE,
    ]


def get_battery_registers() -> list[int]:
    """Get list of registers for battery/power status."""
    return [
        ProMag800Registers.ESTIMATED_BATTERY_LIFETIME,
        ProMag800Registers.ESTIMATED_BATTERY_LIFETIME + 1,
        ProMag800Registers.BATTERY_CHARGE_STATE,
        ProMag800Registers.BATTERY_CHARGE_STATE + 1,
        ProMag800Registers.CAPACITY_BATTERY_1,
        ProMag800Registers.CAPACITY_BATTERY_1 + 1,
        ProMag800Registers.CAPACITY_BATTERY_2,
        ProMag800Registers.CAPACITY_BATTERY_2 + 1,
    ]


def get_diagnostic_registers() -> list[int]:
    """Get list of registers for diagnostics."""
    return [
        ProMag800Registers.ACTUAL_DIAGNOSTICS,
        ProMag800Registers.PREVIOUS_DIAGNOSTICS,
        ProMag800Registers.OPERATING_TIME,
        ProMag800Registers.OPERATING_TIME_FROM_RESTART,
        ProMag800Registers.DIAGNOSTICS_1,
        ProMag800Registers.DIAGNOSTICS_2,
        ProMag800Registers.DIAGNOSTICS_3,
        ProMag800Registers.DIAGNOSTICS_4,
        ProMag800Registers.DIAGNOSTICS_5,
    ]


def get_unit_registers() -> list[int]:
    """Get list of registers for unit settings."""
    return [
        ProMag800Registers.VOLUME_FLOW_UNIT,
        ProMag800Registers.VOLUME_UNIT,
        ProMag800Registers.CONDUCTIVITY_UNIT,
        ProMag800Registers.TEMPERATURE_UNIT,
        ProMag800Registers.PRESSURE_UNIT,
    ]


def get_modbus_config_registers() -> list[int]:
    """Get list of registers for Modbus configuration."""
    return [
        ProMag800Registers.BUS_ADDRESS,
        ProMag800Registers.BAUDRATE,
        ProMag800Registers.PARITY,
        ProMag800Registers.BYTE_ORDER,
        ProMag800Registers.TELEGRAM_DELAY,
        ProMag800Registers.TELEGRAM_DELAY + 1,
        ProMag800Registers.DEVICE_ID,
        ProMag800Registers.DEVICE_REVISION,
        ProMag800Registers.FIELDBUS_WRITING_ACCESS,
    ]


def get_all_essential_registers() -> list[int]:
    """Get combined list of all essential registers for typical monitoring."""
    registers = []
    registers.extend(get_measured_value_registers())
    registers.extend(get_totalizer_registers())
    registers.extend(get_battery_registers())
    registers.extend(get_diagnostic_registers())
    registers.extend(get_unit_registers())
    return sorted(set(registers))
