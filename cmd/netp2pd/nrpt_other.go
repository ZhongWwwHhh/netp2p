//go:build !windows

package main

func enableNRPT(namespace, server string) error { return nil }
func disableNRPT(namespace string) error        { return nil }
