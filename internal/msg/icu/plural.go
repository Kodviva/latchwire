package icu

import "strings"

// PluralCategory is the CLDR cardinal plural category of a non-negative
// whole number for the ten languages of spec goal 5. Rules for fractions are
// left out: Latchwire only counts whole things. Add a language here when its
// rules are not "other only" or "one, other".
func PluralCategory(lang string, n int) string {
	base, _, _ := strings.Cut(strings.ToLower(lang), "-")
	switch base {
	case "zh", "ja", "ko":
		return "other"
	case "ru":
		switch {
		case n%10 == 1 && n%100 != 11:
			return "one"
		case n%10 >= 2 && n%10 <= 4 && (n%100 < 12 || n%100 > 14):
			return "few"
		}
		return "many"
	case "fr", "pt":
		switch {
		case n == 0 || n == 1:
			return "one"
		case n != 0 && n%1000000 == 0:
			return "many"
		}
		return "other"
	case "es":
		switch {
		case n == 1:
			return "one"
		case n != 0 && n%1000000 == 0:
			return "many"
		}
		return "other"
	}
	// en, de, tr and anything unknown.
	if n == 1 {
		return "one"
	}
	return "other"
}
