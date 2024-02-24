package jwtgolang

import "fmt"

func getValidationResponseMsg(field, tag string) string {
	switch tag {
	// TODO Fields
	case "eqcsfield":
		return fmt.Sprintf("The %s field must be equal to another relative field", field)
	case "eqfield":
		return fmt.Sprintf("The %s field must be equal to another field", field)
	case "fieldcontains":
		return fmt.Sprintf("The %s field must contain the indicated characters", field)
	case "fieldexcludes":
		return fmt.Sprintf("The %s field must not contain the indicated characters", field)
	case "gtcsfield":
		return fmt.Sprintf("The %s field must be greater than another relative field", field)
	case "gtecsfield":
		return fmt.Sprintf("The %s field must be greater than or equal to another relative field", field)
	case "gtefield":
		return fmt.Sprintf("The %s field must be greater than or equal to another field", field)
	case "gtfield":
		return fmt.Sprintf("The %s field must be greater than another field", field)
	case "ltcsfield":
		return fmt.Sprintf("The %s field must be less than another relative field", field)
	case "ltecsfield":
		return fmt.Sprintf("The %s field must be less than or equal to another relative field", field)
	case "ltefield":
		return fmt.Sprintf("The %s field must be less than or equal to another field", field)
	case "ltfield":
		return fmt.Sprintf("The %s field must be less than another field", field)
	case "necsfield":
		return fmt.Sprintf("The %s field must not be equal to another relative field", field)
	case "nefield":
		return fmt.Sprintf("The %s field must not be equal to another field", field)
		// TODO Network
	case "cidr":
		return fmt.Sprintf("The %s must be a valid CIDR notation", field)
	case "cidrv4":
		return fmt.Sprintf("The %s must be a valid IPv4 CIDR notation", field)
	case "cidrv6":
		return fmt.Sprintf("The %s must be a valid IPv6 CIDR notation", field)
	case "datauri":
		return fmt.Sprintf("The %s must be a valid Data URI", field)
	case "fqdn":
		return fmt.Sprintf("The %s must be a valid Fully Qualified Domain Name (FQDN)", field)
	case "hostname":
		return fmt.Sprintf("The %s must be a valid Hostname (RFC 952)", field)
	case "hostname_port":
		return fmt.Sprintf("The %s must be a valid HostPort", field)
	case "hostname_rfc1123":
		return fmt.Sprintf("The %s must be a valid Hostname (RFC 1123)", field)
	case "ip":
		return fmt.Sprintf("The %s must be a valid Internet Protocol Address (IP)", field)
	case "ip4_addr":
		return fmt.Sprintf("The %s must be a valid IPv4 Address", field)
	case "ip6_addr":
		return fmt.Sprintf("The %s must be a valid IPv6 Address", field)
	case "ip_addr":
		return fmt.Sprintf("The %s must be a valid Internet Protocol Address (IP)", field)
	case "ipv4":
		return fmt.Sprintf("The %s must be a valid IPv4 Address", field)
	case "ipv6":
		return fmt.Sprintf("The %s must be a valid IPv6 Address", field)
	case "mac":
		return fmt.Sprintf("The %s must be a valid Media Access Control (MAC) Address", field)
	case "tcp4_addr":
		return fmt.Sprintf("The %s must be a valid TCPv4 Address", field)
	case "tcp6_addr":
		return fmt.Sprintf("The %s must be a valid TCPv6 Address", field)
	case "tcp_addr":
		return fmt.Sprintf("The %s must be a valid TCP Address", field)
	case "udp4_addr":
		return fmt.Sprintf("The %s must be a valid UDPv4 Address", field)
	case "udp6_addr":
		return fmt.Sprintf("The %s must be a valid UDPv6 Address", field)
	case "udp_addr":
		return fmt.Sprintf("The %s must be a valid UDP Address", field)
	case "unix_addr":
		return fmt.Sprintf("The %s must be a valid Unix domain socket endpoint Address", field)
	case "uri":
		return fmt.Sprintf("The %s must be a valid URI String", field)
	case "url":
		return fmt.Sprintf("The %s must be a valid URL String", field)
	case "http_url":
		return fmt.Sprintf("The %s must be a valid HTTP URL String", field)
	case "url_encoded":
		return fmt.Sprintf("The %s must be a valid URL Encoded String", field)
	case "urn_rfc2141":
		return fmt.Sprintf("The %s must be a valid URN RFC 2141 String", field)
	// TODO STRING
	case "alpha":
		return fmt.Sprintf("The %s must contain only alphabetic characters", field)
	case "alphanum":
		return fmt.Sprintf("The %s must contain only alphanumeric characters", field)
	case "alphanumunicode":
		return fmt.Sprintf("The %s must contain only alphanumeric Unicode characters", field)
	case "alphaunicode":
		return fmt.Sprintf("The %s must contain only alphabetic Unicode characters", field)
	case "ascii":
		return fmt.Sprintf("The %s must contain only ASCII characters", field)
	case "boolean":
		return fmt.Sprintf("The %s must be a boolean value", field)
	case "contains":
		return fmt.Sprintf("The %s must contain the specified substring", field)
	case "containsany":
		return fmt.Sprintf("The %s must contain any of the specified characters", field)
	case "containsrune":
		return fmt.Sprintf("The %s must contain the specified rune", field)
	case "endsnotwith":
		return fmt.Sprintf("The %s must not end with the specified suffix", field)
	case "endswith":
		return fmt.Sprintf("The %s must end with the specified suffix", field)
	case "excludes":
		return fmt.Sprintf("The %s must not contain the specified substring", field)
	case "excludesall":
		return fmt.Sprintf("The %s must not contain any of the specified characters", field)
	case "excludesrune":
		return fmt.Sprintf("The %s must not contain the specified rune", field)
	case "lowercase":
		return fmt.Sprintf("The %s must be in lowercase", field)
	case "multibyte":
		return fmt.Sprintf("The %s must contain multi-byte characters", field)
	case "number":
		return fmt.Sprintf("The %s must be a number", field)
	case "numeric":
		return fmt.Sprintf("The %s must be numeric", field)
	case "printascii":
		return fmt.Sprintf("The %s must contain only printable ASCII characters", field)
	case "startsnotwith":
		return fmt.Sprintf("The %s must not start with the specified prefix", field)
	case "startswith":
		return fmt.Sprintf("The %s must start with the specified prefix", field)
	case "uppercase":
		return fmt.Sprintf("The %s must be in uppercase", field)
		// TODO FORMAT
	case "base64":
		return fmt.Sprintf("The %s must be a valid Base64 string", field)
	case "base64url":
		return fmt.Sprintf("The %s must be a valid Base64URL string", field)
	case "base64rawurl":
		return fmt.Sprintf("The %s must be a valid Base64RawURL string", field)
	case "bic":
		return fmt.Sprintf("The %s must be a valid Business Identifier Code (BIC)", field)
	case "bcp47_language_tag":
		return fmt.Sprintf("The %s must be a valid Language tag (BCP 47)", field)
	case "btc_addr":
		return fmt.Sprintf("The %s must be a valid Bitcoin Address", field)
	case "btc_addr_bech32":
		return fmt.Sprintf("The %s must be a valid Bitcoin Bech32 Address (segwit)", field)
	case "credit_card":
		return fmt.Sprintf("The %s must be a valid Credit Card Number", field)
	case "mongodb":
		return fmt.Sprintf("The %s must be a valid MongoDB ObjectID", field)
	case "cron":
		return fmt.Sprintf("The %s must be a valid Cron expression", field)
	case "spicedb":
		return fmt.Sprintf("The %s must be a valid SpiceDb ObjectID/Permission/Type", field)
	case "datetime":
		return fmt.Sprintf("The %s must be a valid Datetime", field)
	case "e164":
		return fmt.Sprintf("The %s must be a valid E164 formatted phone number", field)
	case "email":
		return fmt.Sprintf("The %s must be a valid E-mail address", field)
	case "eth_addr":
		return fmt.Sprintf("The %s must be a valid Ethereum Address", field)
	case "hexadecimal":
		return fmt.Sprintf("The %s must be a valid Hexadecimal string", field)
	case "hexcolor":
		return fmt.Sprintf("The %s must be a valid Hexcolor string", field)
	case "hsl":
		return fmt.Sprintf("The %s must be a valid HSL string", field)
	case "hsla":
		return fmt.Sprintf("The %s must be a valid HSLA string", field)
	case "html":
		return fmt.Sprintf("The %s must contain valid HTML tags", field)
	case "html_encoded":
		return fmt.Sprintf("The %s must be a valid HTML Encoded string", field)
	case "isbn":
		return fmt.Sprintf("The %s must be a valid International Standard Book Number (ISBN)", field)
	case "isbn10":
		return fmt.Sprintf("The %s must be a valid International Standard Book Number 10 (ISBN-10)", field)
	case "isbn13":
		return fmt.Sprintf("The %s must be a valid International Standard Book Number 13 (ISBN-13)", field)
	case "issn":
		return fmt.Sprintf("The %s must be a valid International Standard Serial Number (ISSN)", field)
	case "iso3166_1_alpha2":
		return fmt.Sprintf("The %s must be a valid two-letter country code (ISO 3166-1 alpha-2)", field)
	case "iso3166_1_alpha3":
		return fmt.Sprintf("The %s must be a valid three-letter country code (ISO 3166-1 alpha-3)", field)
	case "iso3166_1_alpha_numeric":
		return fmt.Sprintf("The %s must be a valid numeric country code (ISO 3166-1 numeric)", field)
	case "iso3166_2":
		return fmt.Sprintf("The %s must be a valid country subdivision code (ISO 3166-2)", field)
	case "iso4217":
		return fmt.Sprintf("The %s must be a valid currency code (ISO 4217)", field)
	case "json":
		return fmt.Sprintf("The %s must be a valid JSON", field)
	case "jwt":
		return fmt.Sprintf("The %s must be a valid JSON Web Token (JWT)", field)
	case "latitude":
		return fmt.Sprintf("The %s must be a valid Latitude", field)
	case "longitude":
		return fmt.Sprintf("The %s must be a valid Longitude", field)
	case "luhn_checksum":
		return fmt.Sprintf("The %s must have a valid Luhn Algorithm Checksum", field)
	case "postcode_iso3166_alpha2":
		return fmt.Sprintf("The %s must be a valid postcode", field)
	case "postcode_iso3166_alpha2_field":
		return fmt.Sprintf("The %s must be a valid postcode", field)
	case "rgb":
		return fmt.Sprintf("The %s must be a valid RGB string", field)
	case "rgba":
		return fmt.Sprintf("The %s must be a valid RGBA string", field)
	case "ssn":
		return fmt.Sprintf("The %s must be a valid Social Security Number (SSN)", field)
	case "timezone":
		return fmt.Sprintf("The %s must be a valid Timezone", field)
	case "uuid":
		return fmt.Sprintf("The %s must be a valid Universally Unique Identifier (UUID)", field)
	case "uuid3":
		return fmt.Sprintf("The %s must be a valid Universally Unique Identifier (UUID) v3", field)
	case "uuid3_rfc4122":
		return fmt.Sprintf("The %s must be a valid Universally Unique Identifier (UUID) v3 RFC4122", field)
	case "uuid4":
		return fmt.Sprintf("The %s must be a valid Universally Unique Identifier (UUID) v4", field)
	case "uuid4_rfc4122":
		return fmt.Sprintf("The %s must be a valid Universally Unique Identifier (UUID) v4 RFC4122", field)
	case "uuid5":
		return fmt.Sprintf("The %s must be a valid Universally Unique Identifier (UUID) v5", field)
	case "uuid5_rfc4122":
		return fmt.Sprintf("The %s must be a valid Universally Unique Identifier (UUID) v5 RFC4122", field)
	case "uuid_rfc4122":
		return fmt.Sprintf("The %s must be a valid Universally Unique Identifier (UUID) RFC4122", field)
	case "md4":
		return fmt.Sprintf("The %s must be a valid MD4 hash", field)
	case "md5":
		return fmt.Sprintf("The %s must be a valid MD5 hash", field)
	case "sha256":
		return fmt.Sprintf("The %s must be a valid SHA256 hash", field)
	case "sha384":
		return fmt.Sprintf("The %s must be a valid SHA384 hash", field)
	case "sha512":
		return fmt.Sprintf("The %s must be a valid SHA512 hash", field)
	case "ripemd128":
		return fmt.Sprintf("The %s must be a valid RIPEMD-128 hash", field)
	case "ripemd160":
		return fmt.Sprintf("The %s must be a valid RIPEMD-160 hash", field)
	case "tiger128":
		return fmt.Sprintf("The %s must be a valid TIGER128 hash", field)
	case "tiger160":
		return fmt.Sprintf("The %s must be a valid TIGER160 hash", field)
	case "tiger192":
		return fmt.Sprintf("The %s must be a valid TIGER192 hash", field)
	case "semver":
		return fmt.Sprintf("The %s must be a valid Semantic Versioning 2.0.0", field)
	case "ulid":
		return fmt.Sprintf("The %s must be a valid Universally Unique Lexicographically Sortable Identifier (ULID)", field)
	case "cve":
		return fmt.Sprintf("The %s must be a valid Common Vulnerabilities and Exposures Identifier (CVE id)", field)

		// TODO Other
	case "dir":
		return fmt.Sprintf("The %s must be an existing directory", field)
	case "dirpath":
		return fmt.Sprintf("The %s must be a valid directory path", field)
	case "file":
		return fmt.Sprintf("The %s must be an existing file", field)
	case "filepath":
		return fmt.Sprintf("The %s must be a valid file path", field)
	case "image":
		return fmt.Sprintf("The %s must be an image", field)
	case "isdefault":
		return fmt.Sprintf("The %s must be the default", field)
	case "len":
		return fmt.Sprintf("The length of %s must be", field)
	case "max":
		return fmt.Sprintf("The %s exceeds the maximum allowed value", field)
	case "min":
		return fmt.Sprintf("The %s must be at least the minimum allowed value", field)
	case "oneof":
		return fmt.Sprintf("The %s must be one of the specified values", field)
	case "required":
		return fmt.Sprintf("The %s field is required", field)
	case "required_if":
		return fmt.Sprintf("The %s field is required if conditions are met", field)
	case "required_unless":
		return fmt.Sprintf("The %s field is required unless conditions are met", field)
	case "required_with":
		return fmt.Sprintf("The %s field is required with other fields", field)
	case "required_with_all":
		return fmt.Sprintf("The %s field is required with all other fields", field)
	case "required_without":
		return fmt.Sprintf("The %s field is required without other fields", field)
	case "required_without_all":
		return fmt.Sprintf("The %s field is required without all other fields", field)
	case "excluded_if":
		return fmt.Sprintf("The %s field is excluded if conditions are met", field)
	case "excluded_unless":
		return fmt.Sprintf("The %s field is excluded unless conditions are met", field)
	case "excluded_with":
		return fmt.Sprintf("The %s field is excluded with other fields", field)
	case "excluded_with_all":
		return fmt.Sprintf("The %s field is excluded with all other fields", field)
	case "excluded_without":
		return fmt.Sprintf("The %s field is excluded without other fields", field)
	case "excluded_without_all":
		return fmt.Sprintf("The %s field is excluded without all other fields", field)
	case "unique":
		return fmt.Sprintf("The %s field must be unique", field)

	default:
		return fmt.Sprintf("Unknown validation tag '%s' for field '%s'", tag, field)
	}
}
