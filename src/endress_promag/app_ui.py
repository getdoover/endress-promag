from pydoover import ui


class EndressPromagUI:
    def __init__(self, app):
        self.app = app

        self.volume_flow = ui.NumericVariable("volume_flow", "Flow m3/h", precision=2)
        self.mass_flow = ui.NumericVariable("mass_flow", "Flow kg/min", precision=2)
        self.totaliser_1 = ui.NumericVariable("totaliser_1", "Totaliser 1 (m3)", precision=2)
        self.last_read_age = ui.DateTimeVariable("last_read_age", "Time since last read")

        self.no_comms_warning = ui.WarningIndicator("no_comms_warning", f"No Comms To {app.config.meter_name}", hidden=True)
        self.meter_error_warning = ui.WarningIndicator("meter_error_warning", f"{app.config.meter_name} Error", hidden=True)

    def fetch(self):
        return self.volume_flow, self.mass_flow, self.totaliser_1, self.no_comms_warning, self.meter_error_warning

    def update(self):
        self.volume_flow.update(self.app.volume_flow)
        self.mass_flow.update(self.app.mass_flow)
        self.totaliser_1.update(self.app.totaliser_1)
        self.last_read_age.update(self.app.last_read_age)

        self.no_comms_warning.hidden = not self.app.meter_offline
