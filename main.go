package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // Ensure cancel is called at the end to clean up

	agentkeyring, err := GetKeyring(ctx)
	if err != nil {
		log.Fatal(err)
	}
	time.Sleep(1 * time.Second)

	err = agentkeyring.AddKey("test", []byte("Hello World"))
	fmt.Println(err)
	b, err := agentkeyring.ReadKey("test")
	fmt.Println(string(b))
	fmt.Println(err)
	err = agentkeyring.RemoveKey("test")
	fmt.Println(err)
	b, err = agentkeyring.ReadKey("test")
	fmt.Println(string(b))
	fmt.Println(err)
	fmt.Println("----")

	c := make(chan os.Signal, 1)
	signal.Notify(c, syscall.SIGHUP)

	err = agentkeyring.AddKey("test", []byte("Hello World"))
	fmt.Println(err)
	b, err = agentkeyring.ReadKey("test")
	fmt.Println(string(b))
	fmt.Println(err)
	err = agentkeyring.RemoveKey("test")
	fmt.Println(err)
	b, err = agentkeyring.ReadKey("test")
	fmt.Println(string(b))
	fmt.Println(err)

	agentkeyring.Wait()
}
