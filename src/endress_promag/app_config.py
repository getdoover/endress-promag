from pathlib import Path

from pydoover import config


class EndressPromagConfig(config.Schema):
    def __init__(self):
        self.meter_name = config.String("Meter Name", default="Meter 1")

        self.eh_meter_host = config.String("EH Meter Host", default="1.tcp.au.ngrok.io")
        self.eh_meter_port = config.Integer("EH Meter Port", default=80)
        self.eh_meter_password = config.String("EH Meter Password", default="0000")

        self.eh_meter_serial_number = config.String("EH Meter Serial Number", default=None, description="OPTIONAL: If provided, any meter not matching this serial number will be ignored")

        self.no_comms_timeout = config.Integer("No Comms Timeout", default=10, description="Time in minutes after which the meter is considered to be offline")


def export():
    EndressPromagConfig().export(Path(__file__).parents[2] / "doover_config.json", "endress_promag")

if __name__ == "__main__":
    export()
