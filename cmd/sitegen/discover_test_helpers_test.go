package main

import "os"

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }

func readFile(p string) (string, error) { b, err := os.ReadFile(p); return string(b), err }
