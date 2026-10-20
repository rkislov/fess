//go:build linux

// rawload generates bounded synthetic traffic only inside the benchmark veth.
package main

import (
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

func checksum(b []byte) uint16 {
	var n uint32
	for len(b) >= 2 {
		n += uint32(binary.BigEndian.Uint16(b))
		b = b[2:]
	}
	if len(b) > 0 {
		n += uint32(b[0]) << 8
	}
	for n>>16 != 0 {
		n = (n & 65535) + (n >> 16)
	}
	return ^uint16(n)
}
func main() {
	iface := flag.String("interface", "", "isolated fxp veth interface")
	mac := flag.String("destination-mac", "", "peer MAC")
	protocol := flag.String("protocol", "syn", "syn or udp")
	rate := flag.Int("pps", 50000, "offered packets/sec, at most 2000000")
	duration := flag.Duration("duration", 12*time.Second, "at most 60s")
	flag.Parse()
	if !strings.HasPrefix(*iface, "fxp") || *rate < 1 || *rate > 2000000 || *duration <= 0 || *duration > 60*time.Second || (*protocol != "syn" && *protocol != "udp") {
		panic("only bounded isolated fxp benchmark traffic is supported")
	}
	nic, err := net.InterfaceByName(*iface)
	if err != nil {
		panic(err)
	}
	dst, err := net.ParseMAC(*mac)
	if err != nil {
		panic(err)
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, 0)
	if err != nil {
		panic(err)
	}
	defer unix.Close(fd)
	addr := &unix.SockaddrLinklayer{Ifindex: nic.Index, Halen: 6}
	copy(addr.Addr[:], dst)
	proto := byte(6)
	l4len := 20
	if *protocol == "udp" {
		proto = 17
		l4len = 8
	}
	frame := make([]byte, 14+20+l4len)
	copy(frame, dst)
	copy(frame[6:], nic.HardwareAddr)
	binary.BigEndian.PutUint16(frame[12:], 0x0800)
	ip := frame[14:34]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(20+l4len))
	ip[8] = 64
	ip[9] = proto
	copy(ip[12:], net.ParseIP("192.0.2.3").To4())
	copy(ip[16:], net.ParseIP("192.0.2.1").To4())
	binary.BigEndian.PutUint16(ip[10:], checksum(ip))
	l4 := frame[34:]
	binary.BigEndian.PutUint16(l4[2:], 18080)
	if proto == 6 {
		l4[12] = 0x50
		l4[13] = 2
		binary.BigEndian.PutUint16(l4[14:], 65535)
	} else {
		binary.BigEndian.PutUint16(l4[4:], 8)
	}
	pseudo := make([]byte, 12+l4len)
	copy(pseudo, ip[12:20])
	pseudo[9] = proto
	binary.BigEndian.PutUint16(pseudo[10:], uint16(l4len))
	// sendmmsg amortizes syscall overhead; precomputed packets have distinct
	// source ports/sequences and valid checksums. The namespace has no default route.
	const batchSize = 256
	type message struct {
		Header unix.Msghdr
		Length uint32
	}
	frames := make([][]byte, 60000)
	for i := range frames {
		frames[i] = append([]byte(nil), frame...)
		segment := frames[i][34:]
		binary.BigEndian.PutUint16(segment, uint16(1024+i))
		if proto == 6 {
			binary.BigEndian.PutUint32(segment[4:], uint32(i))
			segment[16] = 0
			segment[17] = 0
			copy(pseudo[12:], segment)
			binary.BigEndian.PutUint16(segment[16:], checksum(pseudo))
		}
	}
	rawAddr := unix.RawSockaddrLinklayer{Family: unix.AF_PACKET, Ifindex: int32(nic.Index), Halen: 6}
	copy(rawAddr.Addr[:], dst)
	vectors := make([]unix.Iovec, batchSize)
	messages := make([]message, batchSize)
	for i := range messages {
		messages[i].Header.Name = (*byte)(unsafe.Pointer(&rawAddr))
		messages[i].Header.Namelen = uint32(unsafe.Sizeof(rawAddr))
		messages[i].Header.Iov = &vectors[i]
		messages[i].Header.Iovlen = 1
	}
	start := time.Now()
	end := start.Add(*duration)
	var sent, fail int64
	for time.Now().Before(end) {
		due := int64(time.Since(start).Seconds()*float64(*rate)) + 1
		if sent+fail >= due {
			time.Sleep(100 * time.Microsecond)
			continue
		}
		if due > sent+fail+batchSize {
			due = sent + fail + batchSize
		}
		n := int(due - sent - fail)
		for i := 0; i < n; i++ {
			packet := frames[(int(sent+fail)+i)%len(frames)]
			vectors[i].Base = &packet[0]
			vectors[i].SetLen(len(packet))
		}
		count, _, errno := unix.Syscall6(unix.SYS_SENDMMSG, uintptr(fd), uintptr(unsafe.Pointer(&messages[0])), uintptr(n), 0, 0, 0)
		runtime.KeepAlive(frames)
		runtime.KeepAlive(vectors)
		runtime.KeepAlive(messages)
		runtime.KeepAlive(rawAddr)
		if errno != 0 {
			fail += int64(n)
		} else {
			sent += int64(count)
		}
	}
	elapsed := time.Since(start).Seconds()
	json.NewEncoder(os.Stdout).Encode(map[string]any{"sent": sent, "send_errors": fail, "elapsed_seconds": elapsed, "actual_pps": float64(sent) / elapsed, "requested_pps": *rate, "protocol": *protocol, "frame_bytes": len(frame), "sender": "sendmmsg/256; 60000 precomputed source ports", "cpu_affinity": os.Getenv("FESS_BENCH_GENERATOR_CPUS")})
	if fail > 0 {
		fmt.Fprintln(os.Stderr, "send errors")
		os.Exit(1)
	}
}
