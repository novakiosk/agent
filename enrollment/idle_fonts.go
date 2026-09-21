package enrollment

// idleFontCSSStacks is the agent-side counterpart to the control-plane's
// bounded idle font catalog. Keep this map closed: the wire value is an ID,
// never a CSS fragment supplied by a server or kiosk.
var idleFontCSSStacks = map[string]string{
	"sans":               "sans-serif",
	"serif":              "serif",
	"monospace":          "monospace",
	"adwaita-sans":       "'Adwaita Sans','Noto Sans',sans-serif",
	"cantarell":          "Cantarell,'Noto Sans',sans-serif",
	"open-sans":          "'Open Sans','Noto Sans',sans-serif",
	"droid-sans":         "'Droid Sans','Noto Sans',sans-serif",
	"liberation-sans":    "'Liberation Sans','Noto Sans',sans-serif",
	"noto-sans":          "'Noto Sans',sans-serif",
	"nimbus-sans":        "'Nimbus Sans','Liberation Sans',sans-serif",
	"nimbus-sans-narrow": "'Nimbus Sans Narrow','Nimbus Sans','Liberation Sans',sans-serif",
	"urw-gothic":         "'URW Gothic','Liberation Sans',sans-serif",
	"liberation-serif":   "'Liberation Serif','Noto Serif',serif",
	"noto-serif":         "'Noto Serif',serif",
	"nimbus-roman":       "'Nimbus Roman','Liberation Serif',serif",
	"urw-bookman":        "'URW Bookman','Liberation Serif',serif",
	"stix-two-text":      "'STIX Two Text','Noto Serif',serif",
	"adwaita-mono":       "'Adwaita Mono','Noto Sans Mono',monospace",
	"liberation-mono":    "'Liberation Mono','Noto Sans Mono',monospace",
	"noto-sans-mono":     "'Noto Sans Mono',monospace",
	"nimbus-mono-ps":     "'Nimbus Mono PS','Liberation Mono',monospace",
	"vazirmatn":          "Vazirmatn,'Noto Sans Arabic','Noto Sans',sans-serif",
	"noto-naskh-arabic":  "'Noto Naskh Arabic','Noto Serif',serif",
	"padauk":             "Padauk,'Noto Sans',sans-serif",
	"jomolhari":          "Jomolhari,'Noto Serif',serif",
	"noto-sans-cjk-jp":   "'Noto Sans CJK JP','Noto Sans',sans-serif",
	"noto-sans-cjk-kr":   "'Noto Sans CJK KR','Noto Sans',sans-serif",
	"noto-sans-cjk-sc":   "'Noto Sans CJK SC','Noto Sans',sans-serif",
	"noto-sans-cjk-tc":   "'Noto Sans CJK TC','Noto Sans',sans-serif",
	"noto-sans-cjk-hk":   "'Noto Sans CJK HK','Noto Sans',sans-serif",
}

func idleFontCSSStack(id string) (string, bool) {
	stack, ok := idleFontCSSStacks[id]
	return stack, ok
}

func isIdleFontID(id string) bool {
	_, ok := idleFontCSSStack(id)
	return ok
}
