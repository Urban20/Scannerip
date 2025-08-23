package main

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"sync"
	"time"
)

const TIMEOUT = time.Second * 1

func Escaneo(ip string, puerto int) string {

	con, _ := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, puerto), TIMEOUT)
	if con != nil {
		defer con.Close()
		return fmt.Sprintf("%s -> %d abierto", ip, puerto)
	}

	return ""
}

func Archivar(puerto int) {

	temp, temperr := os.OpenFile("temp.temp", os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0644)
	if temperr == nil {
		temp.Write([]byte(strconv.Itoa(puerto) + "\n"))

	}
	temp.Close()
}

func main() {

	ip := os.Args[1]
	HILOS, _ := strconv.Atoi(os.Args[2])
	fmt.Printf("[+] ip objetivo >> %s\n\n", ip)
	wg := sync.WaitGroup{}
	lim := make(chan struct{}, HILOS)
	for x := range 65535 {
		lim <- struct{}{}
		wg.Add(1)

		go func() {
			defer func() { <-lim }()
			st := Escaneo(ip, x)
			if st != "" {
				fmt.Println(st)
				Archivar(x)

			}
			wg.Done()
		}()

	}
	wg.Wait()
	fmt.Println("[+] finalizado")

}
