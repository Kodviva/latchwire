package desktop

import (
	"slices"
	"strings"
)

// Path is who the user is: someone invited to a server, the owner of one,
// or just looking around.
type Path string

// The answers to the first survey question.
const (
	PathInvited Path = "invited"
	PathOwner   Path = "owner"
	PathExplore Path = "explore"
)

// CardAnswer is what the user says about their smart card.
type CardAnswer string

// The answers to the card question.
const (
	CardPlugged CardAnswer = "plugged"
	CardUnsure  CardAnswer = "unsure"
	CardNone    CardAnswer = "none"
)

// HelpLevel is how much guidance the user wants.
type HelpLevel string

// The answers to the help question.
const (
	HelpGuided HelpLevel = "guided"
	HelpHints  HelpLevel = "hints"
	HelpExpert HelpLevel = "expert"
)

// ServerKind is the kind of server the user connects to.
type ServerKind string

// The server kinds a guide exists for.
const (
	ServerOPNsense ServerKind = "opnsense"
	ServerPfSense  ServerKind = "pfsense"
	ServerMikroTik ServerKind = "mikrotik"
	ServerLinux    ServerKind = "linux"
	ServerOther    ServerKind = "other"
)

// Survey holds the answers of the first-run survey. It carries no secrets.
type Survey struct {
	Path   Path
	Card   CardAnswer
	Help   HelpLevel
	Server ServerKind
}

// StepID names one step of the setup roadmap.
type StepID string

// The steps a roadmap is built from.
const (
	StepCardReady     StepID = "card_ready"
	StepKeyCreated    StepID = "key_created"
	StepBackupOffered StepID = "backup_offered"
	StepPubkeyShared  StepID = "pubkey_shared"
	StepServerAdded   StepID = "server_added"
	StepServerInfo    StepID = "server_info_entered"
	StepConnected     StepID = "connected"
)

// allSteps is every known step, for decoding stored progress.
var allSteps = []StepID{
	StepCardReady, StepKeyCreated, StepBackupOffered, StepPubkeyShared,
	StepServerAdded, StepServerInfo, StepConnected,
}

// Roadmap returns the steps the survey calls for, in order. Expert mode and
// the explore path get none.
func Roadmap(s Survey) []StepID {
	if s.Help == HelpExpert {
		return nil
	}
	switch s.Path {
	case PathInvited:
		return []StepID{StepCardReady, StepKeyCreated, StepBackupOffered, StepPubkeyShared, StepServerInfo, StepConnected}
	case PathOwner:
		return []StepID{StepCardReady, StepKeyCreated, StepBackupOffered, StepServerAdded, StepServerInfo, StepConnected}
	}
	return nil
}

// Progress records which steps are done.
type Progress map[StepID]bool

// Current returns the first step of steps that is not done, or false when
// all of them are.
func (p Progress) Current(steps []StepID) (StepID, bool) {
	for _, s := range steps {
		if !p[s] {
			return s, true
		}
	}
	return "", false
}

// Encode renders the survey as sorted key=value pairs joined by ";".
func (s Survey) Encode() string {
	return "card=" + string(s.Card) + ";help=" + string(s.Help) +
		";path=" + string(s.Path) + ";server=" + string(s.Server)
}

// DecodeSurvey parses the output of [Survey.Encode]. It reports false for a
// value that holds anything but known keys and known constants. The card and
// server answers may be empty; path and help may not.
func DecodeSurvey(v string) (Survey, bool) {
	var s Survey
	seen := map[string]bool{}
	for _, part := range strings.Split(v, ";") {
		k, val, ok := strings.Cut(part, "=")
		if !ok || seen[k] {
			return Survey{}, false
		}
		seen[k] = true
		switch k {
		case "path":
			s.Path = Path(val)
		case "card":
			s.Card = CardAnswer(val)
		case "help":
			s.Help = HelpLevel(val)
		case "server":
			s.Server = ServerKind(val)
		default:
			return Survey{}, false
		}
	}
	okPath := slices.Contains([]Path{PathInvited, PathOwner, PathExplore}, s.Path)
	okHelp := slices.Contains([]HelpLevel{HelpGuided, HelpHints, HelpExpert}, s.Help)
	okCard := s.Card == "" || slices.Contains([]CardAnswer{CardPlugged, CardUnsure, CardNone}, s.Card)
	okServer := s.Server == "" || slices.Contains([]ServerKind{ServerOPNsense, ServerPfSense, ServerMikroTik, ServerLinux, ServerOther}, s.Server)
	if !okPath || !okHelp || !okCard || !okServer {
		return Survey{}, false
	}
	return s, true
}

// Encode renders the done steps as sorted step=1 pairs joined by ";".
func (p Progress) Encode() string {
	var parts []string
	for id, done := range p {
		if done {
			parts = append(parts, string(id)+"=1")
		}
	}
	slices.Sort(parts)
	return strings.Join(parts, ";")
}

// DecodeProgress parses the output of [Progress.Encode]. Unknown steps and
// malformed pairs are dropped. The result is never nil.
func DecodeProgress(v string) Progress {
	p := Progress{}
	for _, part := range strings.Split(v, ";") {
		k, val, ok := strings.Cut(part, "=")
		if ok && val == "1" && slices.Contains(allSteps, StepID(k)) {
			p[StepID(k)] = true
		}
	}
	return p
}
