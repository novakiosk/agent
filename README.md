# NOVA Kiosk Agent

The Linux device agent for [NOVA Kiosk](https://github.com/novakiosk/novakiosk).
It enrolls kiosks with the control plane, maintains their signed connection,
applies assigned content and runtime settings, and reports observed device and
printer state. It is built for the NOVA Kiosk OS and its coordinated protocol;
it is not a standalone kiosk-management product.

The same executable runs the **Print Bridge** on a central CUPS host. That role
manages printer evidence and fixed queue/job operations without the kiosk's
browser, desktop, or machine-operation lifecycle.

## License

This repository is licensed under the [MIT License](LICENSE)
