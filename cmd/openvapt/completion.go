package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
)

// cmdCompletion prints a static completion script built from the command
// table and the real flag sets. Standard library only.
func cmdCompletion(_ context.Context, args []string) error {
	if len(args) != 1 {
		return usageErr("usage: openvapt completion bash|zsh|fish")
	}
	s, err := completionScript(args[0])
	if err != nil {
		return err
	}
	fmt.Fprint(os.Stdout, s)
	return nil
}

// visibleNames lists command names and aliases a user types (not --help forms).
func visibleNames() []string {
	var out []string
	for _, c := range commands {
		out = append(out, c.Name)
		for _, a := range c.Aliases {
			if !strings.HasPrefix(a, "-") {
				out = append(out, a)
			}
		}
	}
	return out
}

func flagNames(fs func() *flag.FlagSet) []string {
	if fs == nil {
		return nil
	}
	var out []string
	fs().VisitAll(func(f *flag.Flag) { out = append(out, "--"+f.Name) })
	sort.Strings(out)
	return out
}

// words returns, for a command, the words offered after it: flags, fixed
// values and subcommand names.
func words(c command) []string {
	w := flagNames(c.Flags)
	w = append(w, c.Values...)
	for _, s := range c.Subs {
		w = append(w, s.Name)
	}
	return w
}

func completionScript(shell string) (string, error) {
	var b strings.Builder
	names := strings.Join(visibleNames(), " ")
	switch shell {
	case "bash":
		b.WriteString("# bash completion for openvapt. Load with: source <(openvapt completion bash)\n_openvapt() {\n  local cur=${COMP_WORDS[COMP_CWORD]} cmd=${COMP_WORDS[1]} sub=${COMP_WORDS[2]}\n")
		fmt.Fprintf(&b, "  if [ \"$COMP_CWORD\" -eq 1 ]; then COMPREPLY=( $(compgen -W %q -- \"$cur\") ); return; fi\n", names)
		b.WriteString("  local w=\"\"\n  case \"$cmd\" in\n")
		for _, c := range commands {
			pat := strings.Join(append([]string{c.Name}, c.Aliases...), "|")
			if len(c.Subs) > 0 {
				fmt.Fprintf(&b, "    %s)\n      case \"$sub\" in\n", pat)
				for _, s := range c.Subs {
					fmt.Fprintf(&b, "        %s) w=%q ;;\n", s.Name, strings.Join(flagNames(s.Flags), " "))
				}
				fmt.Fprintf(&b, "        *) w=%q ;;\n      esac ;;\n", strings.Join(words(c), " "))
				continue
			}
			fmt.Fprintf(&b, "    %s) w=%q ;;\n", pat, strings.Join(words(c), " "))
		}
		b.WriteString("  esac\n  COMPREPLY=( $(compgen -W \"$w\" -- \"$cur\") )\n}\ncomplete -o default -F _openvapt openvapt\n")
	case "zsh":
		b.WriteString("#compdef openvapt\n# zsh completion for openvapt. Load with: source <(openvapt completion zsh)\n_openvapt() {\n  local -a w\n")
		fmt.Fprintf(&b, "  if (( CURRENT == 2 )); then w=(%s); compadd -a w; return; fi\n  case $words[2] in\n", names)
		for _, c := range commands {
			pat := strings.Join(append([]string{c.Name}, c.Aliases...), "|")
			if len(c.Subs) > 0 {
				fmt.Fprintf(&b, "    %s)\n      case $words[3] in\n", pat)
				for _, s := range c.Subs {
					fmt.Fprintf(&b, "        %s) w=(%s) ;;\n", s.Name, strings.Join(flagNames(s.Flags), " "))
				}
				fmt.Fprintf(&b, "        *) w=(%s) ;;\n      esac ;;\n", strings.Join(words(c), " "))
				continue
			}
			fmt.Fprintf(&b, "    %s) w=(%s) ;;\n", pat, strings.Join(words(c), " "))
		}
		b.WriteString("  esac\n  compadd -a w\n  _files\n}\ncompdef _openvapt openvapt\n")
	case "fish":
		b.WriteString("# fish completion for openvapt. Load with: openvapt completion fish | source\ncomplete -c openvapt -f\n")
		for _, c := range commands {
			if strings.HasPrefix(c.Name, "-") {
				continue
			}
			fmt.Fprintf(&b, "complete -c openvapt -n __fish_use_subcommand -a %s -d %q\n", c.Name, c.Summary)
			for _, a := range c.Aliases {
				if !strings.HasPrefix(a, "-") {
					fmt.Fprintf(&b, "complete -c openvapt -n __fish_use_subcommand -a %s -d %q\n", a, c.Summary)
				}
			}
			on := "__fish_seen_subcommand_from " + strings.Join(append([]string{c.Name}, c.Aliases...), " ")
			if c.Flags != nil {
				c.Flags().VisitAll(func(f *flag.Flag) {
					fmt.Fprintf(&b, "complete -c openvapt -n %q -l %s -d %q\n", on, f.Name, f.Usage)
				})
			}
			for _, v := range c.Values {
				fmt.Fprintf(&b, "complete -c openvapt -n %q -a %s\n", on, v)
			}
			for _, s := range c.Subs {
				fmt.Fprintf(&b, "complete -c openvapt -n %q -a %s -d %q\n", on, s.Name, s.Summary)
				if s.Flags != nil {
					s.Flags().VisitAll(func(f *flag.Flag) {
						fmt.Fprintf(&b, "complete -c openvapt -n %q -l %s -d %q\n", "__fish_seen_subcommand_from "+s.Name, f.Name, f.Usage)
					})
				}
			}
		}
	default:
		return "", usageErr("unknown shell %q (use bash, zsh or fish)", shell)
	}
	return b.String(), nil
}
