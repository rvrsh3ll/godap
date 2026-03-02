package ldaputils

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/Macmod/godap/v2/pkg/formats"
	"github.com/go-ldap/ldap/v3"
)

func HexToOffset(hex string) (integer int64) {
	integer, _ = strconv.ParseInt(EndianConvert(hex), 16, 64)
	integer = integer * 2
	return
}

func EndianConvert(sd string) (newSD string) {
	sdBytes, _ := hex.DecodeString(sd)

	for i, j := 0, len(sdBytes)-1; i < j; i, j = i+1, j-1 {
		sdBytes[i], sdBytes[j] = sdBytes[j], sdBytes[i]
	}

	newSD = hex.EncodeToString(sdBytes)

	return
}

func HexToDecimalString(hex string) (decimal string) {
	integer, _ := strconv.ParseInt(hex, 16, 64)
	decimal = strconv.FormatInt(integer, 10)

	return
}

func HexToInt(hex string) (integer int) {
	integer64, _ := strconv.ParseInt(hex, 16, 64)
	integer = int(integer64)
	return
}

func HexToUint32(hex string) uint32 {
	integer64, _ := strconv.ParseUint(hex, 16, 32)
	return uint32(integer64)
}

func Capitalize(str string) string {
	runes := []rune(str)
	if len(runes) > 0 {
		runes[0] = unicode.ToUpper(runes[0])
	}
	return string(runes)
}

func ConvertSID(hexSID string) (SID string) {
	var fields []string
	fields = append(fields, hexSID[0:2])
	if fields[0] == "01" {
		fields[0] = "S-1"
	}
	numDashes, _ := strconv.Atoi(HexToDecimalString(hexSID[2:4]))

	fields = append(fields, "-"+HexToDecimalString(hexSID[4:16]))

	lower, upper := 16, 24
	for i := 1; i <= numDashes; i++ {
		fields = append(fields, "-"+HexToDecimalString(EndianConvert(hexSID[lower:upper])))
		lower += 8
		upper += 8
	}

	for i := 0; i < len(fields); i++ {
		SID += (fields[i])
	}

	return
}

func EncodeSID(sid string) (string, error) {
	if len(sid) < 2 {
		return "", fmt.Errorf("Invalid SID format")
	}

	parts := strings.Split(sid[2:], "-")
	if len(parts) < 3 {
		return "", fmt.Errorf("Invalid SID format")
	}

	hexSID := ""

	revision, err := strconv.Atoi(parts[0])
	if err != nil {
		return "", fmt.Errorf("Error parsing revision: %v", err)
	}

	hexSID += fmt.Sprintf("%02X", revision)

	subAuthoritiesCount := len(parts) - 2
	hexSID += fmt.Sprintf("%02X", subAuthoritiesCount)

	identifierAuthority, _ := strconv.ParseUint(parts[1], 10, 64)
	for i := 0; i < 6; i++ {
		hexSID += fmt.Sprintf("%02X", byte(identifierAuthority>>(8*(5-i))&0xFF))
	}

	for _, subAuthority := range parts[2:] {
		subAuthorityValue, err := strconv.ParseUint(subAuthority, 10, 32)
		if err != nil {
			return "", fmt.Errorf("Error parsing subauthority: %v", err)
		}

		subAuthorityArr := make([]byte, 4)
		binary.LittleEndian.PutUint32(subAuthorityArr, uint32(subAuthorityValue))

		hexSID += fmt.Sprintf("%08X", subAuthorityArr)
	}

	return hexSID, nil
}

func IsSID(s string) bool {
	return strings.HasPrefix(s, "S-")
}

func ConvertGUID(portion string) string {
	portion1 := EndianConvert(portion[0:8])
	portion2 := EndianConvert(portion[8:12])
	portion3 := EndianConvert(portion[12:16])
	portion4 := portion[16:20]
	portion5 := portion[20:]
	return fmt.Sprintf("%s-%s-%s-%s-%s", portion1, portion2, portion3, portion4, portion5)
}

func EncodeGUID(guid string) (string, error) {
	tokens := strings.Split(guid, "-")
	if len(tokens) != 5 {
		return "", fmt.Errorf("Wrong GUID format")
	}

	result := ""
	result += EndianConvert(tokens[0])
	result += EndianConvert(tokens[1])
	result += EndianConvert(tokens[2])
	result += tokens[3]
	result += tokens[4]
	return result, nil
}

func FormatLDAPTime(val, format string, offset int) string {
	layout := "20060102150405.0Z"
	t, err := time.Parse(layout, val)
	if err != nil {
		return "Invalid date format"
	}

	distString := formats.GetTimeDistString(time.Since(t.Add(time.Hour * time.Duration(offset))))

	return fmt.Sprintf("%s %s", t.Format(format), distString)
}

func FormatLDAPTime2(val, format string, offset int) string {
	intValue, err := strconv.ParseInt(val, 10, 64)
	if err != nil {
		return "(Invalid)"
	}

	unixTime := (intValue - 116444736000000000) / 10000000

	nsec := (intValue % 10000000) * 100

	t := time.Unix(unixTime, nsec).UTC().Add(time.Hour * time.Duration(offset))

	diff := time.Now().UTC().Sub(t)
	distString := formats.GetTimeDistString(diff)

	return fmt.Sprintf("%s %s", t.Format(format), distString)
}

func FormatDuration(d time.Duration) string {
	days := d / (24 * time.Hour)
	d -= days * 24 * time.Hour

	hours := d / time.Hour
	d -= hours * time.Hour

	minutes := d / time.Minute
	d -= minutes * time.Minute

	seconds := d / time.Second

	parts := []string{}
	if days > 0 {
		parts = append(parts, fmt.Sprintf("%d days", days))
	}
	if hours > 0 {
		parts = append(parts, fmt.Sprintf("%d hours", hours))
	}
	if minutes > 0 {
		parts = append(parts, fmt.Sprintf("%d minutes", minutes))
	}
	if seconds > 0 {
		parts = append(parts, fmt.Sprintf("%d seconds", seconds))
	}

	if len(parts) == 0 {
		return "0 seconds"
	}
	return strings.Join(parts, " ")
}

func ParseUACFlags(uacInt int) []string {
	uacFlagKeys := make([]int, 0)
	for k := range UacFlags {
		uacFlagKeys = append(uacFlagKeys, k)
	}
	sort.Ints(uacFlagKeys)

	var uacFlagsList []string
	for _, flag := range uacFlagKeys {
		curFlag := UacFlags[flag]
		if uacInt&flag != 0 {
			if curFlag.Present != "" {
				uacFlagsList = append(uacFlagsList, curFlag.Present)
			}
		} else {
			if curFlag.NotPresent != "" {
				uacFlagsList = append(uacFlagsList, curFlag.NotPresent)
			}
		}
	}

	return uacFlagsList
}

func ParseSystemFlags(v uint32) []string {
	sysFlagKeys := make([]uint32, 0)
	for k := range SystemFlags {
		sysFlagKeys = append(sysFlagKeys, k)
	}
	sort.Slice(sysFlagKeys, func(i, j int) bool {
		return sysFlagKeys[i] < sysFlagKeys[j]
	})

	var result []string
	for _, bit := range sysFlagKeys {
		if v&bit != 0 {
			result = append(result, SystemFlags[bit])
		}
	}

	return result
}

func ParseMSDuration(val string) (time.Duration, error) {
	intValue, err := strconv.ParseInt(val, 10, 64)

	if err == nil {
		if intValue < 0 {
			intValue = -intValue
		}

		duration := time.Duration(intValue/10000000) * time.Second
		return duration, nil
	}

	return 0, fmt.Errorf("Invalid duration value")
}

type FormattedAttrValue struct {
	OriginalValue  string
	FormattedValue string
}

type FormattedAttr struct {
	Values []FormattedAttrValue
}

func (e FormattedAttr) ValuesStr() string {
	var values []string
	for _, val := range e.Values {
		values = append(values, val.FormattedValue)
	}

	return strings.Join(values, "; ")
}

func FormatLDAPAttribute(attr *ldap.EntryAttribute, timeFormat string, timeOffset int) FormattedAttr {
	var formattedEntries []string
	var formattedAttrValues []FormattedAttrValue

	if len(attr.Values) < 1 {
		// This should never happen (?)
		return FormattedAttr{[]FormattedAttrValue{{OriginalValue: "(Empty)", FormattedValue: "(Empty)"}}}
	}

	/* Special parsing for bitset expansions */
	if attr.Name == "userAccountControl" || attr.Name == "systemFlags" {
		switch attr.Name {
		case "userAccountControl":
			uacInt, err := strconv.Atoi(attr.Values[0])
			if err == nil {
				formattedEntries = ParseUACFlags(uacInt)
			}
		case "systemFlags":
			intValue, err := strconv.ParseInt(attr.Values[0], 10, 64)
			if err == nil {
				formattedEntries = ParseSystemFlags(uint32(intValue))
			}
		}

		for _, x := range formattedEntries {
			formattedAttrValues = append(formattedAttrValues, FormattedAttrValue{
				OriginalValue:  attr.Values[0],
				FormattedValue: x,
			})
		}

		return FormattedAttr{formattedAttrValues}
	}

	// Regular parsing for other attributes
	for idx, val := range attr.Values {
		// Format the value
		var formattedEntry string
		switch attr.Name {
		case "objectSid":
			formattedEntry = "SID{" + ConvertSID(hex.EncodeToString(attr.ByteValues[idx])) + "}"
		case "objectGUID", "schemaIDGUID":
			formattedEntry = "GUID{" + ConvertGUID(hex.EncodeToString(attr.ByteValues[idx])) + "}"
		case "whenCreated", "whenChanged":
			formattedEntry = FormatLDAPTime(val, timeFormat, timeOffset)
		case "lastLogonTimestamp", "accountExpires", "badPasswordTime", "lastLogoff", "lastLogon", "pwdLastSet", "creationTime", "lockoutTime":
			if val == "0" || (attr.Name == "accountExpires" && val == "9223372036854775807") {
				formattedEntry = "(Never)"
			} else {
				formattedEntry = FormatLDAPTime2(val, timeFormat, timeOffset)
			}
		case "primaryGroupID":
			rId, _ := strconv.Atoi(val)

			groupName, ok := RidMap[rId]

			if ok {
				formattedEntry = groupName
			}
		case "sAMAccountType":
			sAMAccountTypeId, _ := strconv.Atoi(val)

			accountType, ok := SAMAccountTypeMap[sAMAccountTypeId]

			if ok {
				formattedEntry = accountType
			}
		case "groupType":
			groupTypeId, _ := strconv.Atoi(val)
			groupType, ok := GroupTypeMap[groupTypeId]

			if ok {
				formattedEntry = groupType
			}
		case "instanceType":
			instanceTypeId, _ := strconv.Atoi(val)
			instanceType, ok := InstanceTypeMap[instanceTypeId]

			if ok {
				formattedEntry = instanceType
			}
		case "logonHours", "dSASignature":
			formattedEntry = "HEX{" + hex.EncodeToString(attr.ByteValues[idx]) + "}"
		case "msDS-MaximumPasswordAge", "msDS-MinimumPasswordAge", "msDS-LockoutDuration", "msDS-LockoutObservationWindow", "lockoutDuration", "lockOutObservationWindow", "maxPwdAge", "minPwdAge", "forceLogoff", "msDS-UserTGTLifetime", "msDS-ComputerTGTLifetime", "msDS-ServiceTGTLifetime":
			duration, err := ParseMSDuration(val)
			if err == nil {
				if attr.Name == "forceLogoff" {
					switch val {
					case "0":
						formattedEntry = "(Instantly)"
					case "-9223372036854775808":
						formattedEntry = "(Never)"
					default:
						formattedEntry = FormatDuration(duration)
					}
				} else {
					if (duration / time.Second) == 0 {
						formattedEntry = "(None)"
					} else {
						formattedEntry = FormatDuration(duration)
					}
				}
			}
		case "lockoutThreshold", "msDS-LockoutThreshold", "minPwdLength", "msDS-MinimumPasswordLength":
			intValue, err := strconv.ParseInt(val, 10, 64)
			if err == nil {
				if intValue == 0 {
					formattedEntry = "(None)"
				}
			}
		}

		// Append the formatted entry, or the original value if no formatting was applied
		if formattedEntry == "" {
			formattedEntry = val
		}

		formattedAttrValues = append(formattedAttrValues, FormattedAttrValue{
			OriginalValue:  val,
			FormattedValue: formattedEntry,
		})
	}

	return FormattedAttr{formattedAttrValues}
}
