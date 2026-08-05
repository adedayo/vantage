package vantage

import (
	"context"
	"fmt"
	"strings"
)

//RFC: https://tools.ietf.org/html/rfc7208

// LookupSPF returns the SPF record on a domain if it exists
// https://tools.ietf.org/html/rfc7208#section-4.6.1
func LookupSPF(ctx context.Context, r Resolver, domain string) (SPFRecord, error) {
	txts, err := LookupTXT(ctx, r, domain)

	if err == nil {
		for _, txt := range txts {
			txt = strings.TrimSpace(txt)
			if strings.HasPrefix(txt, "v=spf1") {
				spf := SPFRecord{
					Domain: domain,
					Raw:    txt,
				}

				fields := strings.Fields(txt)
				for _, f := range fields {
					fs := strings.Split(f, ":")
					mechanism := fs[0]
					value := ""
					if len(fs) > 1 {
						value = fs[1]
					}
					switch mechanism {
					case "all", "+all", "-all", "~all":
						m := Directive{
							Mechanism: "all",
							Qualifier: getQualifier(mechanism),
							Value:     value,
						}
						spf.BasicMechanisms = append(spf.BasicMechanisms, m)
					case "include", "+include", "-include":
						m := Directive{
							Mechanism: "include",
							Qualifier: getQualifier(mechanism),
							Value:     value,
						}
						spf.BasicMechanisms = append(spf.BasicMechanisms, m)

					case "a", "+a", "-a":
						m := Directive{
							Mechanism: "a",
							Qualifier: getQualifier(mechanism),
							Value:     value,
						}
						spf.DesignatedSenderMechanisms = append(spf.DesignatedSenderMechanisms, m)

					case "mx", "+mx", "-mx":
						m := Directive{
							Mechanism: "mx",
							Qualifier: getQualifier(mechanism),
							Value:     value,
						}
						spf.DesignatedSenderMechanisms = append(spf.DesignatedSenderMechanisms, m)

					case "ip4", "+ip4", "-ip4":
						m := Directive{
							Mechanism: "ip4",
							Qualifier: getQualifier(mechanism),
							Value:     value,
						}
						spf.DesignatedSenderMechanisms = append(spf.DesignatedSenderMechanisms, m)

					case "ip6", "+ip6", "-ip6":
						m := Directive{
							Mechanism: "ip6",
							Qualifier: getQualifier(mechanism),
							Value:     value,
						}
						spf.DesignatedSenderMechanisms = append(spf.DesignatedSenderMechanisms, m)

					case "exists", "+exists", "-exists":
						m := Directive{
							Mechanism: "exists",
							Qualifier: getQualifier(mechanism),
							Value:     value,
						}
						spf.DesignatedSenderMechanisms = append(spf.DesignatedSenderMechanisms, m)

					case "ptr", "+ptr", "-ptr": // Do not use this
						m := Directive{
							Mechanism: "ptr",
							Qualifier: getQualifier(mechanism),
							Value:     value,
						}
						spf.DesignatedSenderMechanisms = append(spf.DesignatedSenderMechanisms, m)

					default:
						m := Directive{
							Mechanism: mechanism,
							Qualifier: getQualifier(mechanism),
							Value:     value,
						}
						spf.DesignatedSenderMechanisms = append(spf.DesignatedSenderMechanisms, m)
					}
				}
				return spf, nil
			}
		}
		return SPFRecord{}, fmt.Errorf("no SPF record found on %s", domain)
	}
	return SPFRecord{}, err
}

// SPFRecord represents the SPF record for a domain
type SPFRecord struct {
	Domain                     string
	Raw                        string
	BasicMechanisms            []Directive
	DesignatedSenderMechanisms []Directive
}

// Directive is SPF Directive
type Directive struct {
	Qualifier string
	Mechanism string
	Value     string
}

func getQualifier(mechanism string) (q string) {
	if len(mechanism) > 0 {
		switch mechanism[0] {
		case '-':
			return "-"
		case '~':
			return "~"
		case '?':
			return "?"
		case '+':
			return "+"
		default:
			return
		}
	}
	return
}
