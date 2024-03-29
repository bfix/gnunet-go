// Code generated by enum generator; DO NOT EDIT.

//nolint:stylecheck // allow non-camel-case for constants
package enums

//----------------------------------------------------------------------
// Resource Record Flags
//----------------------------------------------------------------------

// GNSFlag type
type GNSFlag uint16

const (
	// GNS record flags

	GNS_FLAG_CRITICAL GNSFlag = (1<<(15-15)) // This record is critical. If it cannot be processed (for example because the record type is unknown) resolution MUST fail

	GNS_FLAG_SHADOW GNSFlag = (1<<(15-14)) // This record should not be used unless all (other) records in the set with an absolute expiration time have expired.

	GNS_FLAG_SUPPLEMENTAL GNSFlag = (1<<(15-13)) // This is a supplemental record.

	GNS_FLAG_RELATIVE_EXPIRATION GNSFlag = (1<<(15-1)) // This expiration time of the record is a relative time (not an absolute time). Used in GNUnet implementation.

	GNS_FLAG_PRIVATE GNSFlag = (1<<(15-0)) // This is a private record of this peer and it should thus not be published.

)

// List flags as strings
func (gf GNSFlag) List() (flags []string) {
	if gf&GNS_FLAG_PRIVATE != 0 {
		flags = append(flags, "Private")
	}
	if gf&GNS_FLAG_SHADOW != 0 {
		flags = append(flags, "Shadow")
	}
	if gf&GNS_FLAG_SUPPLEMENTAL != 0 {
		flags = append(flags, "Suppl")
	}
	if gf&GNS_FLAG_CRITICAL != 0 {
		flags = append(flags, "Critical")
	}
	if gf&GNS_FLAG_RELATIVE_EXPIRATION != 0 {
		flags = append(flags, "TTL")
	}
	return
}
