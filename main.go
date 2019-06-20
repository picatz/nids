package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"

	"github.com/robertkrimen/otto"
)

var (
	rulesFile      string
	rulesSetupFile string
	iface          string
	filter         string
	promiscuous    bool
	immediate      bool
	snapLen        int
)

func init() {
	flag.StringVar(&filter, "filter", "", "apply bpf filter to capture")
	flag.StringVar(&rulesSetupFile, "rules-setup", "", "use a given file containing code to help setup rules")
	flag.StringVar(&rulesFile, "rules", "", "use a given file containing the rules to evaluate")
	flag.StringVar(&iface, "interface", "", "network interface to listen on")
	flag.BoolVar(&promiscuous, "promiscuous", false, "capture in promiscuous mode")
	flag.BoolVar(&immediate, "immediate", false, "capture in immediate mode")
	flag.IntVar(&snapLen, "spap-len", 65536, "capture in promiscuous mode")
	flag.Parse()
}

const hexDigit = "0123456789abcdef"

func hardwareAddrString(a []byte) string {
	if len(a) == 0 {
		return ""
	}
	buf := make([]byte, 0, len(a)*3-1)
	for i, b := range a {
		if i > 0 {
			buf = append(buf, ':')
		}
		buf = append(buf, hexDigit[b>>4])
		buf = append(buf, hexDigit[b&0xF])
	}
	return string(buf)
}

type dumpLayer struct {
	Name string
	Info gopacket.Layer
}

func packetToJSON(packet gopacket.Packet) (string, error) {
	dumpLayers := []dumpLayer{}
	for _, layer := range packet.Layers() {
		dumped := dumpLayer{
			Name: fmt.Sprintf("%v", layer.LayerType()),
			Info: layer,
		}
		dumpLayers = append(dumpLayers, dumped)
	}
	b, err := json.Marshal(dumpLayers)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func main() {
	vm := otto.New()

	var code string

	if rulesFile == "" {
		code = "console.log(JSON.stringify(packet))"
	} else {
		bytes, err := ioutil.ReadFile(rulesFile)
		if err != nil {
			panic(err)
		}
		code = string(bytes)
	}
	if rulesSetupFile != "" {
		bytes, err := ioutil.ReadFile(rulesSetupFile)
		if err != nil {
			panic(err)
		}
		_, err = vm.Run(string(bytes))
		if err != nil {
			panic(err)
		}
	}
	if iface == "" {
		panic("no interface given")
	}
	inactive, err := pcap.NewInactiveHandle(iface)
	if err != nil {
		panic(err)
	}
	defer inactive.CleanUp()

	inactive.SetSnapLen(snapLen)
	inactive.SetPromisc(promiscuous)
	inactive.SetImmediateMode(immediate)

	handle, err := inactive.Activate()
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	if filter != "" {
		err = handle.SetBPFFilter(filter)
		if err != nil {
			panic(err)
		}
	}

	dec, _ := gopacket.DecodersByLayerName["Ethernet"]
	source := gopacket.NewPacketSource(handle, dec)
	source.NoCopy = true

	var packet gopacket.Packet

	var containsLayer = func(call otto.FunctionCall) otto.Value {
		lookingFor := call.Argument(0).String()
		for _, layer := range packet.Layers() {
			if fmt.Sprintf("%v", layer.LayerType()) == lookingFor {
				return otto.TrueValue()
			}
		}
		return otto.FalseValue()
	}

	var layerIndex = func(call otto.FunctionCall) otto.Value {
		lookingFor := call.Argument(0).String()
		for index, layer := range packet.Layers() {
			if fmt.Sprintf("%v", layer.LayerType()) == lookingFor {
				val, err := otto.ToValue(index)
				if err == nil {
					return val
				}
			}
		}
		return otto.Value{}
	}

	var hardwareAddrStr = func(call otto.FunctionCall) otto.Value {
		base64Str := call.Argument(0).String()
		data, err := base64.StdEncoding.DecodeString(base64Str)
		if err == nil {
			dataStr := hardwareAddrString(data)
			val, err := otto.ToValue(dataStr)
			if err == nil {
				return val
			}
		}
		return otto.Value{}
	}

	var hexdump = func(call otto.FunctionCall) otto.Value {
		base64Str := call.Argument(0).String()
		data, err := base64.StdEncoding.DecodeString(base64Str)
		if len(data) > 0 && err == nil {
			dataStr := strings.TrimSpace(hex.Dump(data))
			val, err := otto.ToValue(dataStr)
			if err == nil {
				return val
			}
		}
		return otto.Value{}
	}

	var prettyPacket = func(call otto.FunctionCall) otto.Value {
		val, err := otto.ToValue(packet.String())
		if err == nil {
			return val
		}
		return otto.Value{}
	}

	vm.Set("layerIndex", layerIndex)
	vm.Set("containsLayer", containsLayer)
	vm.Set("hardwareAddrStr", hardwareAddrStr)
	vm.Set("hexdump", hexdump)
	vm.Set("prettyPacket", prettyPacket)

	for packet = range source.Packets() {
		packetJSONStr, err := packetToJSON(packet)
		if err != nil {
			panic(err)
		}
		vm.Set("packet", packetJSONStr)
		vm.Run("packet = JSON.parse(packet)")
		_, err = vm.Run(code)
		if err != nil {
			panic(err)
		}
	}
}
