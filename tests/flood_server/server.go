package main

import (
	"flag"
	"fmt"
	"kaze/kaze"
	"os"
	"slices"
)

func main() {
	name := flag.String("name", "kaze_test", "channel name")
	bufSize := flag.Int("buf", 8192, "buffer size")
	_ = kaze.Unlink(*name) // Unlink any existing channel with the same name
	k, err := kaze.Create(*name, *bufSize, kaze.OptReset())
	if err != nil {
		panic(err)
	}
	defer k.CloseAndUnlink()

	data := make([]byte, 100)
	fmt.Printf("start server with name=%s, bufSize=%d\n", *name, *bufSize)
	for k.IsClosed().NotReady() {
		ctx, err := k.ReadContext()
		if err == kaze.ErrAgain {
			err = ctx.Wait()
		}
		if err == os.ErrClosed {
			break
		}
		if err != nil {
			panic(err)
		}
		if !slices.Equal(data, ctx.Buffer()) {
			panic(fmt.Sprintf("data mismatch: %v", ctx.Buffer()))
		}
		err = ctx.Commit(len(data))
		if err == os.ErrClosed {
			break
		}
		if err != nil {
			panic(err)
		}
	}
	fmt.Printf("server closed\n")
}
