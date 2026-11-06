// Package assets embeds the app's fonts (SIL Open Font License, see the
// OFL-*.txt files; static instances of the variable fonts) and icons.
package assets

import _ "embed"

var (
	//go:embed fonts/Inter-Regular.ttf
	InterRegular []byte
	//go:embed fonts/Inter-SemiBold.ttf
	InterSemiBold []byte
	//go:embed fonts/SpaceGrotesk-Bold.ttf
	SpaceGroteskBold []byte
	//go:embed fonts/JetBrainsMono-Regular.ttf
	JetBrainsMono []byte
	//go:embed tray.svg
	TrayIcon []byte
	//go:embed icon.svg
	AppIcon []byte
)
