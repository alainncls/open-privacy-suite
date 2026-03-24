package main

type Perspective struct {
	Active   bool
	UserID   string
	UserName string
	Level    int // 1=read-only reporting, 2=full impersonation
}

func (p *Perspective) Label() string {
	if p == nil || !p.Active {
		return ""
	}
	switch p.Level {
	case 2:
		return "[IMPERSONATING: " + p.UserName + "]"
	default:
		return "[PERSPECTIVE: " + p.UserName + " (approximate — read-only)]"
	}
}
