package tracer

var tracerEventTypeNames = map[tracerEventType]string{
	tracerEventTypeFORK: "fork",
	tracerEventTypeEXEC: "exec",
	tracerEventTypeEXIT: "exit",
}

func (t tracerEventType) String() string {
	if name, found := tracerEventTypeNames[t]; found {
		return name
	}

	return "unknown"
}
