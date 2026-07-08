from pydoover.tags import Tag, Tags


class EndressPromagTags(Tags):
    volume_flow = Tag("number", default=None, live=True)
    mass_flow = Tag("number", default=None)
    conductivity = Tag("number", default=None)
    totaliser_1 = Tag("number", default=None)

    # Timestamp (unix milliseconds) of the last successful read from the meter.
    # Milliseconds because it backs a uiTimestamp element (see app_ui).
    last_read_time = Tag("number", default=None)

    # True while the meter is contactable. Drives the "no comms" warning's
    # hidden state (the warning shows when this is False).
    meter_online = Tag("boolean", default=True)
    # True while the meter has no active diagnostic. Drives the "meter error"
    # warning's hidden state (the warning shows when this is False).
    meter_ok = Tag("boolean", default=True)
