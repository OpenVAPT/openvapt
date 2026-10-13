// Package terms is the single source of truth for how OpenVAPT describes
// itself and for the acknowledgements every user must accept. The command
// line tool and the website generator both read from here, so the wording a
// user agrees to on the website is word for word what the tool asks them to
// accept before a scan.
package terms

// Version changes whenever the acknowledgements change.
const Version = "1.0 (2026-10-13)"

// Tagline is the one-line positioning used in headers and banners.
const Tagline = "Academic. Non-commercial. Open-source code. Free to download and use, for your own use, 100% at your own risk."

// Pillar is one part of the positioning, shown as a card on the website.
type Pillar struct {
	Title string
	Text  string
}

// Pillars explain the positioning in plain words.
var Pillars = []Pillar{
	{"Academic", "Made for learning and open review. It shows, in public, how a vulnerability assessment tool is designed, built and tested."},
	{"Non-Commercial", "Nothing is sold and nothing ever will be. The project earns no money and offers no paid services, support or advice."},
	{"Open-Source Code", "Every line of code is public on GitHub to read, study, review and improve. Nothing is hidden."},
	{"Free to Download and Use", "Free of charge for anyone: individuals, students, schools and companies."},
	{"For Your Own Use", "Use it for your personal use or your business use, on computers and servers you own or control, for your own purposes only."},
	{"Not for Sale or Services", "You may not sell it, and you may not use it to provide services to anyone else, paid or unpaid."},
	{"100% at Your Own Risk", "It comes as is, with no warranty. You alone carry every risk and every consequence. The developers accept no responsibility."},
}

// Acknowledgements are the statements a user must accept. They are shown as
// a checklist before download on the website, and printed and accepted
// (by typing I ACCEPT) before every scan. Nothing about the acceptance is
// stored or sent anywhere.
var Acknowledgements = []string{
	"I have read, studied and understood the End User Licence Agreement, the Disclaimer, the Acceptable Use Policy and the Licence.",
	"I understand that OpenVAPT is an academic, non-commercial project made for learning, and that it is not a penetration test, an audit, a certification, a service or professional advice.",
	"I will download and use OpenVAPT only for my own use, personal or business, and only on computers and servers that I own or control, or for which I have the owner's permission.",
	"I will not sell OpenVAPT, include it in a product, or use it to provide services of any kind to anyone else, paid or unpaid.",
	"I understand that automated results can be wrong or incomplete, and that a report without findings does not prove a system is secure.",
	"I acknowledge, agree to and accept that I use OpenVAPT 100% at my own risk, and that I alone am responsible for every risk and every consequence, including damage, data loss, downtime, security incidents and legal liability.",
	"I agree that the developers and contributors provide OpenVAPT as is, without any warranty, and accept no responsibility or liability of any kind, to the fullest extent the law allows.",
	"I am solely responsible for complying with all laws that apply to me, including the Computer Crimes Act 1997 and the Cyber Security Act 2024 in Malaysia, and the laws of my own country.",
}

// AcceptPhrase is what a user types to accept the acknowledgements in the CLI.
const AcceptPhrase = "I ACCEPT"
