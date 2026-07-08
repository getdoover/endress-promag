from pathlib import Path

from pydoover import config
from pydoover.config import ApplicationPosition
from pydoover.docker.modbus import ModbusConfig


class EndressPromagConfig(config.Schema):
    meter_name = config.String("Meter Name", default="Meter 1")

    max_flow = config.Number(
        "Max Flow",
        default=None,
        description="Maximum flow in m3/h. Only used for display purposes. Leave blank to disable.",
    )

    units = config.Enum(
        "Volume Units",
        choices=["m³", "L"],
        default="m³",
        description="Display unit for volume flow and totaliser. The meter reports m³; select L to convert to litres (×1000).",
    )

    eh_meter_host = config.String(
        "EH Meter IP Host",
        default=None,
        description="EH Meter IP Host. Default is 192.168.1.212",
    )
    eh_meter_port = config.Integer("EH Meter IP Port", default=80)
    eh_meter_password = config.String("EH Meter Password", default="0000")

    modbus_id = config.Integer(
        "Modbus ID",
        default=None,
        description="Modbus ID. Default is 1. If this is set, the EH Meter IP Host and Port will be ignored and the Modbus connection will be used instead.",
    )
    modbus_config = ModbusConfig()

    eh_meter_serial_number = config.String(
        "EH Meter Serial Number",
        default=None,
        description="OPTIONAL: If provided, any meter not matching this serial number will be ignored",
    )
    no_comms_timeout = config.Integer(
        "No Comms Timeout",
        default=10,
        description="Time in minutes after which the meter is considered to be offline",
    )

    position = ApplicationPosition()


def export():
    EndressPromagConfig.export(
        Path(__file__).parents[2] / "doover_config.json", "endress_promag"
    )


if __name__ == "__main__":
    export()
