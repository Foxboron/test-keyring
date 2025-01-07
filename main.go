package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
)

func main() {

	agentkeyring, err := GetKeyring()
	if err != nil {
		log.Fatal(err)
	}
	err = agentkeyring.AddKey("this works", []byte("test"))
	if err != nil {
		fmt.Println(err)
	}
	err = agentkeyring.AddKey("this works again", []byte("test"))
	if err != nil {
		fmt.Println(err)
	}

	// Comment out this line, and everything works
	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGHUP)

	err = agentkeyring.AddKey("this works does not work", []byte("test"))
	if err != nil {
		fmt.Println(err)
	}
}
