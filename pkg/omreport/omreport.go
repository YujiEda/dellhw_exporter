package omreport

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"strings"
)

// Options allow to set options for the OMReport package
type Options struct {
	OMReportExecutable string
}

// OMReport contains the Options and a Reader to mock outputs during development
type OMReport struct {
	Options *Options
	Reader  func(func([]string), string, ...string)
}

// Value contains a metrics name, value and labels
type Value struct {
	Name   string
	Value  string
	Labels map[string]string
}

// RedfishChassisPower1 contains a metrics OdataId, Name and Status for json
type RedfishStatus struct {
	OdataID string `json:"@odata.id"`
	Name    string `json:"Name"`
	Status  struct {
		Health string `json:Health`
		State  string `json:State`
	} `json:"Status"`
}

type BmcAddress struct {
	IPv4 struct {
		Address string `json:"address"`
	} `json:ipv4`
}
type BmcUser struct {
	Support struct {
		Password struct {
			Raw string `json:"raw"`
		} `json:"password"`
	} `json:support`
}

const (
	// DefaultOMReportExecutable the default path of the omreport binary
	DefaultOMReportExecutable = "/opt/dell/srvadmin/bin/omreport"

	indexField = "Index"
)

// New returns a new *OMReport
func New(opts *Options) *OMReport {
	if opts.OMReportExecutable == "" {
		opts.OMReportExecutable = DefaultOMReportExecutable
	}
	return &OMReport{
		Options: opts,
		Reader:  readOmreport,
	}
}

func readOmreport(f func([]string), omreportExecutable string, args ...string) {
	args = append(args, "-fmt", "ssv")
	_ = readCommand(func(line string) error {
		sp := strings.Split(line, ";")
		for i, s := range sp {
			sp[i] = clean(s)
		}
		f(sp)
		return nil
	}, omreportExecutable, args...)
}

var client *http.Client
var results = make(map[string][]byte)

func (or *OMReport) getOMReportExecutable() string {
	if or.Options != nil {
		return or.Options.OMReportExecutable
	}
	return DefaultOMReportExecutable
}

func (or *OMReport) readReport(f func([]string), omreportExecutable string, args ...string) {
	or.Reader(f, omreportExecutable, args...)
}

// Chassis returns the chassis status
/*
func (or *OMReport) Chassis() ([]Value, error) {
	values := []Value{}
	or.readReport(func(fields []string) {
		if len(fields) != 2 || fields[0] == "SEVERITY" {
			return
		}
		component := strings.Replace(fields[1], " ", "_", -1)
		values = append(values, Value{
			Name:   "chassis_status",
			Value:  severity(fields[0]),
			Labels: map[string]string{"component": component},
		})
	}, or.getOMReportExecutable(), "chassis")
	return values, nil
}
*/
func (or *OMReport) Chassis() ([]Value, error) {

	address, err := ioutil.ReadFile("/etc/neco/bmc-address.json")
	if err != nil {
		log.Fatal(err)
	}
	BmcAddress := BmcAddress{}
	if err := json.Unmarshal(address, &BmcAddress); err != nil {
		log.Fatal(err)
	}

	user, err := ioutil.ReadFile("/etc/neco/bmc-user.json")
	if err != nil {
		log.Fatal(err)
	}
	BmcUser := BmcUser{}
	if err := json.Unmarshal(user, &BmcUser); err != nil {
		log.Fatal(err)
	}

	client = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
	values := []Value{}
	urls := []string{
		"https://support:" + BmcUser.Support.Password.Raw + "@" + BmcAddress.IPv4.Address + "/redfish/v1/Chassis/System.Embedded.1",
		"https://support:" + BmcUser.Support.Password.Raw + "@" + BmcAddress.IPv4.Address + "/redfish/v1/Chassis/System.Embedded.1/Power/PowerSupplies/PSU.Slot.1",
		"https://support:" + BmcUser.Support.Password.Raw + "@" + BmcAddress.IPv4.Address + "/redfish/v1/Chassis/System.Embedded.1/Power/PowerSupplies/PSU.Slot.2",
	}
	RedfishStatus := RedfishStatus{}

	for _, v := range urls {
		resp, err := client.Get(v)
		if err != nil {
			panic(err.Error())
		}
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			log.Fatal(err)
		}

		if resp.StatusCode != http.StatusOK {
			fmt.Printf("%s", body)
		}
		err = json.Unmarshal(body, &RedfishStatus)
		if err != nil {
			fmt.Println(err.Error())
		}

		values = append(values, Value{
			Name:   "chassis_status",
			Value:  severity(RedfishStatus.Status.Health),
			Labels: map[string]string{"component": strings.Replace(RedfishStatus.Name, " ", "_", -1)},
		})
	}

	// sample string data
	values = append(values, Value{
		Name:   "chassis_status",
		Value:  severity("Ok"),
		Labels: map[string]string{"component": "Processors"},
	})
	return values, nil
}

// Fans returns the fan status and if supported RPM reading
func (or *OMReport) Fans() ([]Value, error) {
	values := []Value{}
	or.readReport(func(fields []string) {
		if len(fields) != 8 {
			return
		}
		if _, err := strconv.Atoi(fields[0]); err != nil {
			return
		}
		ts := map[string]string{"fan": replace(fields[2])}
		values = append(values, Value{
			Name:   "chassis_fan_status",
			Value:  severity(fields[1]),
			Labels: ts,
		})
		fs := strings.Fields(fields[3])
		if len(fs) == 2 && fs[1] == "RPM" {
			values = append(values, Value{
				Name:   "chassis_fan_reading",
				Value:  fs[0],
				Labels: ts,
			})
		}
	}, or.getOMReportExecutable(), "chassis", "fans")
	return values, nil
}

// Memory returns the memory status
func (or *OMReport) Memory() ([]Value, error) {
	values := []Value{}
	or.readReport(func(fields []string) {
		if len(fields) != 5 {
			return
		}
		if _, err := strconv.Atoi(fields[0]); err != nil {
			return
		}
		values = append(values, Value{
			Name:   "chassis_memory_status",
			Value:  severity(fields[1]),
			Labels: map[string]string{"memory": replace(fields[2])},
		})
	}, or.getOMReportExecutable(), "chassis", "memory")
	return values, nil
}

// System returns the system status
func (or *OMReport) System() ([]Value, error) {
	values := []Value{}
	or.readReport(func(fields []string) {
		if len(fields) != 2 || fields[0] == "SEVERITY" {
			return
		}
		component := strings.Replace(fields[1], " ", "_", -1)
		values = append(values, Value{
			Name:   "system_status",
			Value:  severity(fields[0]),
			Labels: map[string]string{"component": component},
		})
	}, or.getOMReportExecutable(), "system")
	return values, nil
}

// StorageBattery returns the storage battery ("RAID batteries")
func (or *OMReport) StorageBattery() ([]Value, error) {
	values := []Value{}
	or.readReport(func(fields []string) {
		if len(fields) < 3 || fields[0] == "ID" {
			return
		}
		id := strings.Replace(fields[0], ":", "_", -1)
		values = append(values, Value{
			Name:   "storage_battery_status",
			Value:  severity(fields[1]),
			Labels: map[string]string{"controller": id},
		})
	}, or.getOMReportExecutable(), "storage", "battery")
	return values, nil
}

// StorageController returns the storage controller status
func (or *OMReport) StorageController() ([]Value, error) {
	values := []Value{}
	or.readReport(func(fields []string) {
		if len(fields) < 3 || fields[0] == "ID" {
			return
		}
		or.StoragePdisk(fields[0])
		id := strings.Replace(fields[0], ":", "_", -1)
		values = append(values, Value{
			Name:   "storage_controller_status",
			Value:  severity(fields[1]),
			Labels: map[string]string{"id": id},
		})
	}, or.getOMReportExecutable(), "storage", "controller")
	return values, nil
}

// StorageEnclosure returns the storage enclosure status
func (or *OMReport) StorageEnclosure() ([]Value, error) {
	values := []Value{}
	or.readReport(func(fields []string) {
		if len(fields) < 3 || fields[0] == "ID" {
			return
		}
		id := strings.Replace(fields[0], ":", "_", -1)
		values = append(values, Value{
			Name:   "storage_enclosure_status",
			Value:  severity(fields[1]),
			Labels: map[string]string{"enclosure": id},
		})
	}, or.getOMReportExecutable(), "storage", "enclosure")
	return values, nil
}

// StoragePdisk is called from the controller func, since it needs the encapsulating IDs.
func (or *OMReport) StoragePdisk(cid string) ([]Value, error) {
	values := []Value{}
	or.readReport(func(fields []string) {
		if len(fields) < 3 || fields[0] == "ID" {
			return
		}
		// Need to find out what the various ID formats might be
		id := strings.Replace(fields[0], ":", "_", -1)
		values = append(values, Value{
			Name:  "storage_pdisk_status",
			Value: severity(fields[1]),
			Labels: map[string]string{
				"controller": cid,
				"disk":       id,
			},
		})
	}, or.getOMReportExecutable(), "storage", "pdisk", "controller="+cid)
	return values, nil
}

// StorageVdisk returns the storage vdisk status
func (or *OMReport) StorageVdisk() ([]Value, error) {
	values := []Value{}
	or.readReport(func(fields []string) {
		if len(fields) < 3 || fields[0] == "ID" {
			return
		}
		id := strings.Replace(fields[0], ":", "_", -1)
		values = append(values, Value{
			Name:   "storage_vdisk_status",
			Value:  severity(fields[1]),
			Labels: map[string]string{"vdisk": id},
		})
	}, or.getOMReportExecutable(), "storage", "vdisk")
	return values, nil
}

// Ps returns the power supply state and if supported input/output wattage
func (or *OMReport) Ps() ([]Value, error) {
	values := []Value{}
	or.readReport(func(fields []string) {
		if len(fields) < 3 || fields[0] == indexField {
			return
		}
		id := strings.Replace(fields[0], ":", "_", -1)
		ts := map[string]string{"id": id}
		values = append(values, Value{
			Name:   "ps_status",
			Value:  severity(fields[1]),
			Labels: ts,
		})
		if len(fields) < 6 {
			return
		}
		if fields[4] != "" {
			iWattage, err := extract(fields[4], "W")
			if err == nil {
				values = append(values, Value{
					Name:   "ps_rated_input_wattage",
					Value:  iWattage,
					Labels: ts,
				})
			}
		}
		if fields[5] != "" {
			oWattage, err := extract(fields[5], "W")
			if err == nil {
				values = append(values, Value{
					Name:   "ps_rated_output_wattage",
					Value:  oWattage,
					Labels: ts,
				})
			}
		}
	}, or.getOMReportExecutable(), "chassis", "pwrsupplies")
	return values, nil
}

// Nics returns the connection status of the NICs
func (or *OMReport) Nics() ([]Value, error) {
	values := []Value{}
	or.readReport(func(fields []string) {
		if len(fields) < 6 || fields[0] == indexField {
			return
		}
		id := strings.Replace(fields[0], ":", "_", -1)
		ts := map[string]string{"id": id, "device": fields[1]}
		var ret string
		if fields[4] == "Connected" {
			ret = "0"
		} else {
			ret = "1"
		}
		values = append(values, Value{
			Name:   "nic_status",
			Value:  ret,
			Labels: ts,
		})
	}, or.getOMReportExecutable(), "chassis", "nics")
	return values, nil
}

// PsAmpsSysboardPwr returns the power supply system board amps power consumption
func (or *OMReport) PsAmpsSysboardPwr() ([]Value, error) {
	values := []Value{}
	or.readReport(func(fields []string) {
		if len(fields) == 2 && strings.Contains(fields[0], "Current") {
			iFields := strings.Split(fields[0], "Current")
			vFields := strings.Fields(fields[1])
			if len(iFields) < 2 && len(vFields) < 2 {
				return
			}
			id := strings.Replace(iFields[0], " ", "", -1)
			values = append(values, Value{
				Name:   "chassis_current_reading",
				Value:  vFields[0],
				Labels: map[string]string{"pwrsupply": id},
			})
		} else if len(fields) == 6 && (fields[2] == "System Board Pwr Consumption" || fields[2] == "System Board System Level") {
			vFields := strings.Fields(fields[3])
			warnFields := strings.Fields(fields[4])
			failFields := strings.Fields(fields[5])
			if len(vFields) < 2 || len(warnFields) < 2 || len(failFields) < 2 {
				return
			}
			values = append(values, Value{
				Name:   "chassis_power_reading",
				Value:  vFields[0],
				Labels: nil,
			})
			values = append(values, Value{
				Name:   "chassis_power_warn_level",
				Value:  warnFields[0],
				Labels: nil,
			})
			values = append(values, Value{
				Name:   "chassis_power_fail_level",
				Value:  failFields[0],
				Labels: nil,
			})
		}
	}, or.getOMReportExecutable(), "chassis", "pwrmonitoring")
	return values, nil
}

// Processors returns the processors status
func (or *OMReport) Processors() ([]Value, error) {
	values := []Value{}
	or.readReport(func(fields []string) {
		if len(fields) != 8 {
			return
		}
		if _, err := strconv.Atoi(fields[0]); err != nil {
			return
		}
		values = append(values, Value{
			Name:   "chassis_processor_status",
			Value:  severity(fields[1]),
			Labels: map[string]string{"processor": replace(fields[2])},
		})
	}, or.getOMReportExecutable(), "chassis", "processors")
	return values, nil
}

// Temps returns the temperatures for the chassis including the min and max,
// for the max value, warning and failure thresholds are returned
func (or *OMReport) Temps() ([]Value, error) {
	values := []Value{}
	or.readReport(func(fields []string) {
		if len(fields) != 8 {
			return
		}
		if _, err := strconv.Atoi(fields[0]); err != nil {
			return
		}
		ts := map[string]string{"component": replace(fields[2])}
		values = append(values, Value{
			Name:   "chassis_temps",
			Value:  severity(fields[1]),
			Labels: ts,
		})
		fs := strings.Fields(fields[3])
		if len(fs) == 2 && fs[1] == "C" {
			values = append(values, Value{
				Name:   "chassis_temps_reading",
				Value:  fs[0],
				Labels: ts,
			})
		}
		minWarningThreshold := strings.Fields(fields[4])
		if len(minWarningThreshold) == 2 && minWarningThreshold[1] == "C" {
			values = append(values, Value{
				Name:   "chassis_temps_min_warning",
				Value:  minWarningThreshold[0],
				Labels: ts,
			})
		}
		maxWarningThreshold := strings.Fields(fields[5])
		if len(maxWarningThreshold) == 2 && maxWarningThreshold[1] == "C" {
			values = append(values, Value{
				Name:   "chassis_temps_max_warning",
				Value:  maxWarningThreshold[0],
				Labels: ts,
			})
		}
		minFailureThreshold := strings.Fields(fields[6])
		if len(minFailureThreshold) == 2 && minFailureThreshold[1] == "C" {
			values = append(values, Value{
				Name:   "chassis_temps_min_failure",
				Value:  minFailureThreshold[0],
				Labels: ts,
			})
		}
		maxFailureThreshold := strings.Fields(fields[7])
		if len(maxFailureThreshold) == 2 && maxFailureThreshold[1] == "C" {
			values = append(values, Value{
				Name:   "chassis_temps_max_failure",
				Value:  maxFailureThreshold[0],
				Labels: ts,
			})
		}
	}, or.getOMReportExecutable(), "chassis", "temps")
	return values, nil
}

// Volts returns the chassis volts statud and if support reading
func (or *OMReport) Volts() ([]Value, error) {
	values := []Value{}
	or.readReport(func(fields []string) {
		if len(fields) != 8 {
			return
		}
		if _, err := strconv.Atoi(fields[0]); err != nil {
			return
		}
		ts := map[string]string{"component": replace(fields[2])}
		values = append(values, Value{
			Name:   "chassis_volts_status",
			Value:  severity(fields[1]),
			Labels: ts,
		})
		if i, err := extract(fields[3], "V"); err == nil {
			values = append(values, Value{
				Name:   "chassis_volts_reading",
				Value:  i,
				Labels: ts,
			})
		}
	}, or.getOMReportExecutable(), "chassis", "volts")
	return values, nil
}

// ChassisBatteries retursn the chassis batteries status
func (or *OMReport) ChassisBatteries() ([]Value, error) {
	values := []Value{}
	or.readReport(func(fields []string) {
		if len(fields) < 4 || fields[0] == indexField {
			return
		}
		id := strings.Replace(fields[0], ":", "_", -1)
		ts := map[string]string{"id": id}

		values = append(values, Value{
			Name:   "cmos_batteries_status",
			Value:  severity(fields[1]),
			Labels: ts,
		})
	}, or.getOMReportExecutable(), "chassis", "batteries")
	return values, nil
}
