package cupsjob

import (
	"context"
	"github.com/novakiosk/agent/printer"
	"strings"
)

func addUSBQueue(ctx context.Context, config HelperConfig, runner CommandRunner, request Request) Result {
	failure := failureFor(request, ErrorQueueNotAllowed)
	id := strings.TrimPrefix(request.QueueName, "NOVA_USB_")
	if config.Profile != "kiosk" || !hashPattern.MatchString(id) || request.QueueName != printer.USBQueueName(id) {
		return failure
	}
	// Discovery is privileged in CUPS. Only the fixed USB backend is queried;
	// the unprivileged caller never supplies a device URI or driver path.
	output, _, err := runner.Run(ctx, "/usr/sbin/lpinfo", []string{"--include-schemes", "usb", "-v"}, nil)
	if err != nil {
		failure.Error = classifyHelperError(err)
		return failure
	}
	uri, name := "", ""
	for line := range strings.SplitSeq(string(output), "\n") {
		if !strings.HasPrefix(line, "direct ") {
			continue
		}
		candidate := strings.TrimSpace(strings.TrimPrefix(line, "direct "))
		serial, model, ok := printer.ZebraUSBURI(candidate)
		if !ok || printer.USBDeviceID(serial) != id {
			continue
		}
		if uri != "" {
			return failure
		}
		uri, name = candidate, model
	}
	if uri == "" {
		return failure
	}
	output, _, err = runner.Run(ctx, "/usr/bin/lpstat", []string{"-e"}, nil)
	if err != nil {
		failure.Error = classifyHelperError(err)
		return failure
	}
	if len(strings.TrimSpace(string(output))) > 0 {
		for queue := range strings.SplitSeq(strings.TrimSpace(string(output)), "\n") {
			if !SafeQueueName(queue) || strings.EqualFold(queue, request.QueueName) {
				return failure
			}
		}
		output, _, err = runner.Run(ctx, "/usr/bin/lpstat", []string{"-v"}, nil)
		if err != nil {
			failure.Error = classifyHelperError(err)
			return failure
		}
	}
	for line := range strings.SplitSeq(string(output), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if !strings.HasPrefix(line, "device for ") {
			return failure
		}
		pair := strings.SplitN(strings.TrimPrefix(line, "device for "), ": ", 2)
		if len(pair) != 2 || !SafeQueueName(pair[0]) {
			return failure
		}
		// Never overwrite an existing queue or create a duplicate physical printer.
		if strings.EqualFold(pair[0], request.QueueName) {
			return failure
		}
		if serial, _, ok := printer.ZebraUSBURI(strings.TrimSpace(pair[1])); ok && printer.USBDeviceID(serial) == id {
			return failure
		}
	}
	if _, _, err = runner.Run(ctx, "/usr/sbin/lpadmin", []string{"-p", request.QueueName, "-E", "-v", uri, "-m", "drv:///sample.drv/zebra.ppd", "-D", name, "-o", "printer-is-shared=false"}, nil); err != nil {
		failure.Error = classifyHelperError(err)
		return failure
	}
	output, _, err = runner.Run(ctx, "/usr/bin/lpstat", []string{"-v", request.QueueName}, nil)
	if err != nil {
		failure.Error = classifyHelperError(err)
		return failure
	}
	if strings.TrimSpace(string(output)) != "device for "+request.QueueName+": "+uri {
		failure.Error = ErrorCommandFailed
		return failure
	}
	return Result{Version: Version, Type: QueueResultType, Profile: request.Profile, Action: request.Action, CommandHash: request.CommandHash, QueueName: request.QueueName, Result: ResultApplied}
}
