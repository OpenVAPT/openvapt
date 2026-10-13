// Package terms is the single source of truth for how OpenVAPT describes
// itself and for the acknowledgements every user must accept. The command
// line tool and the website generator both read from here, so the wording a
// user agrees to on the website is word for word what the tool asks them to
// accept before a scan.
package terms

// Version changes whenever the acknowledgements change.
const Version = "1.6 (2026-10-13)"

// Tagline is the one-line positioning used in headers and banners.
const Tagline = "Academic. Non-commercial. Built by AI Cybersecurity Engineers. Open, source-available code. Free to download and use, for your own personal or business use, 100% at your own risk."

// Pillar is one part of the positioning, shown as a card on the website.
type Pillar struct {
	Title string
	Text  string
}

// Pillars explain the positioning in plain words.
var Pillars = []Pillar{
	{"Academic", "Made for learning and open review. It shows, in public, how a vulnerability assessment tool is designed, built and tested."},
	{"Non-Commercial", "Nothing is sold. The project is not a business, earns no money, accepts no payments or donations, and offers no paid or unpaid services, support or advice."},
	{"Built by AI Cybersecurity Engineers", "All code, tests, documentation, the website and the legal drafts were researched, developed and built by AI Cybersecurity Engineers (Claude by Anthropic, and OpenAI Codex), directed and approved by the human project owner. They are AI systems, not people or registered engineers, and provide no professional service. It may contain mistakes and has not been audited by an independent human expert."},
	{"Open, Source-Available Code", "Every line of code is public on GitHub to read, study, review and improve within the licence. Licensed under the OpenVAPT Source-Available Licence 1.2, it is not \"open source\" in the formal OSI sense, because selling and providing services are not licensed."},
	{"Free to Download and Use", "Free of charge for anyone: individuals, students, schools and companies."},
	{"For Your Own Use", "Download it to your own server for personal testing, or use it to test your own company's servers with your company's authorisation. For your own purposes only."},
	{"Not for Sale or Services", "You may not sell it, and you may not provide any service to anyone else with anything from or produced by OpenVAPT, paid or unpaid."},
	{"100% at Your Own Risk", "It is a free gift that comes as is, with no warranty. You alone carry every risk and every consequence. To the fullest extent the law allows, the developers accept no responsibility."},
}

// Acknowledgements are the statements a user must accept. They are shown as
// a checklist before download on the website, and printed and accepted
// (by typing I ACCEPT) before every scan. Nothing about the acceptance is
// stored or sent anywhere.
var Acknowledgements = []string{
	"I have read, studied and understood the End User Licence Agreement, the Disclaimer, the Acceptable Use Policy and the Licence.",
	"I understand that OpenVAPT is an academic, non-commercial project made for learning, and that it is not a penetration test, an audit, a certification, a service or professional advice.",
	"I will download and use OpenVAPT only for my own use, personal or business, and only on computers and servers that I own or control, or that my employer owns or controls and has authorised me to assess.",
	"I will not sell OpenVAPT, include it in a product, or use it to provide services of any kind to anyone else, paid or unpaid.",
	"I understand that automated results can be wrong or incomplete, and that a report without findings does not prove a system is secure.",
	"I acknowledge, agree to and accept that I use OpenVAPT 100% at my own risk, and that I alone am responsible for every risk and every consequence, including damage, data loss, downtime, security incidents and legal liability.",
	"I agree that OpenVAPT is a free gift from people who are not in business, provided as is, without any warranty, and that, to the fullest extent the law allows, the developers and contributors owe me no duty and accept no responsibility or liability of any kind, and I release them from every claim.",
	"I am solely responsible for complying with all laws that apply to me, including the Computer Crimes Act 1997 and the Cyber Security Act 2024 in Malaysia, and the laws of my own country.",
	"I understand that OpenVAPT's code, documentation, website and legal texts were researched, developed, built and reviewed by AI Cybersecurity Engineers (AI systems, not people or registered engineers) under the direction of the project owner, may contain mistakes, and have not been audited by a human security expert or drafted or reviewed by a human lawyer.",
}

// AcceptPhrase is what a user types to accept the acknowledgements in the CLI.
const AcceptPhrase = "I ACCEPT"
