package academy

// Glossary terms added with the access control and logging modules (P15 and
// P16). They live in their own file so streams adding terms do not collide,
// and are merged into Glossary before any module is read.
var glossaryAccessLogging = map[string]string{
	"Authentication":       "Proving who a user or program is, for example with a password, a key or a one-time code.",
	"Authorisation":        "Deciding what an authenticated user or program may do, such as which files it may read or which commands it may run.",
	"Separation of Duties": "Splitting a sensitive task between people or roles so that no single account can both make and approve a change unseen.",
	"Login Shell":          "The program started when an account logs in; a nologin or false shell means the account cannot be used interactively.",
	"PAM":                  "Pluggable Authentication Modules: the Linux framework that decides how logins are checked, including lockout after failed attempts.",
	"umask":                "The default permission mask applied to every new file and directory; a stricter mask keeps new files private.",
	"Audit Log":            "A record written by the kernel's audit system of security-relevant events, such as a file opened or a privilege used.",
	"Log Rotation":         "Regularly closing, compressing and eventually deleting old log files so logs stay readable and never fill the disk.",
	"Time Synchronisation": "Keeping a machine's clock in step with trusted time servers, so events on different systems can be ordered correctly.",
	"Intrusion Prevention": "Automatically blocking a source after repeated suspicious behaviour, for example failed logins seen in the log.",
	"Correlation":          "Putting events from several logs or machines together in time order to see one incident as a whole.",
}

func init() {
	for k, v := range glossaryAccessLogging {
		if _, dup := Glossary[k]; dup {
			panic("duplicate glossary term " + k)
		}
		Glossary[k] = v
	}
}
