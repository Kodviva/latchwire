package agent

// newGUIPrompter asks for the PIN with an osascript dialog.
func newGUIPrompter() Prompter { return newOsascriptPrompter() }
