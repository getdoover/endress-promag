from pydoover import ui


class EndressPromagUI:
    def __init__(self, app):
        self.app = app

        volume_ranges = None
        if app.config.max_flow.value is not None:
            max_flow = app.config.max_flow.value
            volume_ranges = [
                ui.Range(min_val=0, max_val=int(max_flow*0.2), colour=ui.Colour.blue),
                ui.Range(min_val=int(max_flow*0.2), max_val=int(max_flow*0.8), colour=ui.Colour.green),
                ui.Range(min_val=int(max_flow*0.8), max_val=int(max_flow), colour=ui.Colour.yellow),
            ]

        self.volume_flow = ui.NumericVariable("volume_flow", "Flow m3/h", precision=2, ranges=volume_ranges, form="radialGauge" if volume_ranges else None)
        self.mass_flow = ui.NumericVariable("mass_flow", "Flow kg/min", precision=2)
        self.conductivity = ui.NumericVariable("conductivity", "Conductivity uS/cm", precision=2)
        self.totaliser_1 = ui.NumericVariable("totaliser_1", "Totaliser 1 (m3)", precision=2)
        self.last_read_age = ui.DateTimeVariable("last_read_age", "Time since last read")

        self.no_comms_warning = ui.WarningIndicator("no_comms_warning", f"No Comms To {app.config.meter_name.value}", hidden=True)
        self.meter_error_warning = ui.WarningIndicator("meter_error_warning", f"{app.config.meter_name.value} Error", hidden=True)

    def fetch(self):
        return self.volume_flow, self.mass_flow, self.conductivity, self.totaliser_1, self.last_read_age, self.no_comms_warning, self.meter_error_warning

    def update(self):
        self.volume_flow.update(self.app.volume_flow)
        self.mass_flow.update(self.app.mass_flow)
        self.conductivity.update(self.app.conductivity)
        self.totaliser_1.update(self.app.totaliser_1)
        self.last_read_age.update(self.app.last_read_age)

        self.no_comms_warning.hidden = not self.app.meter_offline
