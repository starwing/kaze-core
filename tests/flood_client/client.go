package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/starwing/kaze-core/kaze"
)

func main() {
	name := flag.String("name", "kaze_test", "channel name")
	count := flag.Int("count", 10000000, "number of operations")
	k, err := kaze.Open(*name)
	if err != nil {
		panic(err)
	}
	defer k.Close()

	data := make([]byte, 100) // Example data to write

	n := *count
	fmt.Printf("start client with name=%s, count=%d\n", *name, n)
	before := time.Now()
	var after time.Time
	waitCount, waitTime := 0, 0
	for i := range n {
		ctx, err := k.WriteContext(len(data))
		if err != nil {
			if err == kaze.ErrAgain {
				waitCount++
				waitTimeStart := time.Now()
				err = ctx.Wait()
				waitTime += int(time.Since(waitTimeStart).Nanoseconds())
			}
		}
		if err == os.ErrClosed {
			break
		}
		if err != nil {
			panic(err)
		}

		buf := ctx.Buffer()
		if len(buf) < len(data) {
			panic(fmt.Sprintf("buffer too small: %d < %d", len(buf), len(data)))
		}
		copy(ctx.Buffer(), data)
		err = ctx.Commit(len(data))
		if err == os.ErrClosed {
			break
		}
		if err != nil {
			panic(err)
		}

		if i > 0 && (i%5000000) == 0 {
			after = time.Now()
			fmt.Printf("wait count=%d %.3f%% time=%.3f s\n",
				waitCount, float64(waitCount)*100.0/float64(i), float64(waitTime)/1.0e9)
			fmt.Printf("Elapsed time: %.3f s/%d op, %.2f op/s, %d ns/op\n",
				float64(after.Sub(before).Nanoseconds())/1.0e9, i,
				float64(i)*1e9/float64(after.Sub(before).Nanoseconds()),
				int(after.Sub(before).Nanoseconds()/int64(i)))
		}
	}
	after = time.Now()
	fmt.Printf("wait count=%d %.3f%% time=%.3f s\n",
		waitCount, float64(waitCount)*100.0/float64(n), float64(waitTime)/1.0e9)
	fmt.Printf("Elapsed time: %.3f s/%d op, %.2f op/s, %d ns/op\n",
		float64(after.Sub(before).Nanoseconds())/1.0e9, n,
		float64(n)*1e9/float64(after.Sub(before).Nanoseconds()),
		int(after.Sub(before).Nanoseconds()/int64(n)))
}
