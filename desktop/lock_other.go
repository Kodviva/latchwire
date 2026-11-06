//go:build !unix

package main

func singleInstance() (release func(), ok bool) { return func() {}, true }
