package agent

// newGUIPrompter asks for the PIN with pinentry.
func newGUIPrompter() Prompter { return newPinentryPrompter() }
