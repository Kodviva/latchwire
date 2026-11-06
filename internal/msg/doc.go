package msg

// Adding or changing a message:
//
//  1. Edit locales/en.arb. Texts are ICU MessageFormat ({name}, plural,
//     select). "@ID" holds the translators' description and, for a
//     placeholder that is not a plain %s, its printf verb.
//  2. Add the same key to every other locales/*.arb. TestCatalogsComplete
//     fails until they agree.
//  3. Run go generate ./internal/msg, which rewrites en.go.
//
// en.go keeps compile-time printf constants, so the CLI and the daemon call
// fmt with them and always print English. The desktop app renders messages
// in the user's language: Render for UI messages (the UI prefix) and
// Translate for English text that reached it from the daemon or the agent.

//go:generate go run ./gen
