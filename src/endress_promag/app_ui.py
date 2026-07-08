from pydoover import ui

from .app_tags import EndressPromagTags


class EndressPromagUI(ui.UI):
    volume_flow = ui.NumericVariable(
        "Flow",
        units="m³/h",
        value=EndressPromagTags.volume_flow,
        precision=2,
    )
    mass_flow = ui.NumericVariable(
        "Mass Flow",
        units="kg/min",
        value=EndressPromagTags.mass_flow,
        precision=2,
        hidden=True,
    )
    conductivity = ui.NumericVariable(
        "Conductivity",
        units="µS/cm",
        value=EndressPromagTags.conductivity,
        precision=2,
    )
    totaliser_1 = ui.NumericVariable(
        "Totaliser 1",
        units="m³",
        value=EndressPromagTags.totaliser_1,
        precision=2,
    )
    last_read = ui.Timestamp(
        "Last Read",
        value=EndressPromagTags.last_read_time,
    )

    no_comms_warning = ui.WarningIndicator(
        "No Comms",
        name="no_comms_warning",
        hidden=EndressPromagTags.meter_online,
    )
    meter_error_warning = ui.WarningIndicator(
        "Meter Error",
        name="meter_error_warning",
        hidden=EndressPromagTags.meter_ok,
    )

    async def setup(self):
        meter_name = self.config.meter_name.value
        self.no_comms_warning.display_name = f"No Comms To {meter_name}"
        self.meter_error_warning.display_name = f"{meter_name} Error"

        # Mass flow is only available over the WiFi interface; the ProMag 800
        # Modbus interface is volumetric and has no mass flow reading.
        self.mass_flow.hidden = self.config.modbus_id.value is not None

        # Volume unit (m³ or litres). The meter reports m³; when litres is
        # selected the application scales values by 1000, so the display units
        # and the gauge bands must scale to match.
        litres = self.config.units.value == "L"
        factor = 1000 if litres else 1
        self.volume_flow.units = "L/h" if litres else "m³/h"
        self.totaliser_1.units = "L" if litres else "m³"

        # When a max flow is configured, promote the flow reading to a radial
        # gauge with coloured bands. max_flow is configured in m³/h, so scale it
        # into the display unit alongside the flow value.
        max_flow = self.config.max_flow.value
        if max_flow is not None:
            max_flow = max_flow * factor
            self.volume_flow.form = ui.Widget.radial
            self.volume_flow.ranges = [
                ui.Range("Low", 0, int(max_flow * 0.2), ui.Colour.blue),
                ui.Range("Good", int(max_flow * 0.2), int(max_flow * 0.8), ui.Colour.green),
                ui.Range("High", int(max_flow * 0.8), int(max_flow), ui.Colour.yellow),
            ]


def export():
    from pathlib import Path

    EndressPromagUI(None, None, None).export(
        Path(__file__).parents[2] / "doover_config.json", "endress_promag"
    )
