import ipaddress # pragma: no cover
import socket  # pragma: no cover
import sys  # pragma: no cover
from utils import arg_parser  # pragma: no cover
from utils.zhuban_exceptions import InvalidServerResponse  # pragma: no cover
from dns.dns_enums import ResourceRecordType  # pragma: no cover


def main():  # pragma: no cover
    args = arg_parser.parse_args(sys.argv[1:])

    try:
        answer = args.func(args)
    except socket.timeout:
        print("timed out", file=sys.stderr)
        sys.exit(1)
    except socket.gaierror:
        print("address-related error", file=sys.stderr)
        sys.exit(1)
    except InvalidServerResponse:
        print("invalid server response", file=sys.stderr)
        sys.exit(1)
    except ConnectionError:
        print('connection-related error', file=sys.stderr)
        sys.exit(1)

    print('Server response: ' + answer.header.response_type.name, end='\n\n')
    for answer in answer.answers:
        if answer.type_ == ResourceRecordType.A:
            print('domain name: ' + answer.name)
            print('IPv4: ' + answer.data.ip)
        elif answer.type_ == ResourceRecordType.AAAA:
            print('domain name: ' + answer.name)
            print('IPv6: ' + ipaddress.IPv6Address(answer.data.ip).compressed)
        elif answer.type_ == ResourceRecordType.PTR:
            print('IPv4: ' + answer.name.strip(".in-addr.arpa"))
            print('domain name: ' + answer.data.name)


if __name__ == '__main__':  # pragma: no cover
    main()
