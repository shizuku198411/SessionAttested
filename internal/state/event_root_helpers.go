package state

import "session-attested/internal/model"

func AuditWindowFrom(start, end string) model.AuditWindow {
	return model.AuditWindow{StartRFC3339: start, EndRFC3339: end}
}
