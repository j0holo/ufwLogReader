# ufwLogReader

ufwLogReader reads ufw log files and displays which IP addresses did invalid request and which port numbers they requested.

NOTE: this has only been tested on ufw log files with the low priority setting.

## Example

   Example of its output:

   	IP: 127.0.0.2	Amount of requests: 2

		Port Number	Amount
		23		2

	IP: 127.0.0.1	Amount of requests: 10

		Port Number	Amount
		22		8
		23		2


	Total amount of requests: 12
	Most requestsed port: 22

## License

See [LICENSE.md](LICENSE.md) for for details