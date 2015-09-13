//Copyright 2013 Thomson Reuters Global Resources. BSD License please see License file for more information

package ntlm

import (
	"bytes"
	"encoding/binary"
)

type NegotiateMessage struct {
	// sig - 8 bytes
	Signature []byte
	// message type - 4 bytes
	MessageType uint32
	// negotiate flags - 4bytes
	NegotiateFlags uint32
	// If the NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED flag is not set in NegotiateFlags,
	// indicating that no DomainName is supplied in Payload  - then this should have Len 0 / MaxLen 0
	// this contains a domain name
	DomainNameFields *PayloadStruct
	// If the NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED flag is not set in NegotiateFlags,
	// indicating that no WorkstationName is supplied in Payload - then this should have Len 0 / MaxLen 0
	WorkstationFields *PayloadStruct
	// version - 8 bytes
	Version *VersionStruct
	// payload - variable
	Payload       []byte
	PayloadOffset int
}

func (n *NegotiateMessage) Bytes() []byte {
	buffer := &bytes.Buffer{}

	workstationOffset := uint16(32)
	domainOffset := workstationOffset + n.WorkstationFields.Len

	buffer.Write(n.Signature)
	binary.Write(buffer, binary.LittleEndian, n.MessageType)
	binary.Write(buffer, binary.LittleEndian, n.NegotiateFlags)
	binary.Write(buffer, binary.LittleEndian, n.DomainNameFields.Len) // domain string length - 2 bytes
	binary.Write(buffer, binary.LittleEndian, n.DomainNameFields.Len) // domain string length - 2 bytes (repeat)
	binary.Write(buffer, binary.LittleEndian, domainOffset)           // domain offset - 2 bytes
	buffer.Write(zeroBytes(2))
	binary.Write(buffer, binary.LittleEndian, n.WorkstationFields.Len) // host string length - 2 bytes
	binary.Write(buffer, binary.LittleEndian, n.WorkstationFields.Len) // host string length - 2 bytes (repeat)
	binary.Write(buffer, binary.LittleEndian, workstationOffset)       // domain offset - 2 bytes
	buffer.Write(zeroBytes(2))
	buffer.Write(n.DomainNameFields.Bytes())
	buffer.Write(n.WorkstationFields.Bytes())

	return buffer.Bytes()
}
